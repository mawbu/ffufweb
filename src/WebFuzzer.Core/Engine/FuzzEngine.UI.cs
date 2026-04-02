// FuzzEngine.UI.cs — Overload constructor cho WPF UI
// Thêm file này vào WebFuzzer.Core/Engine/
// FuzzEngine nhận thêm callbacks để update UI realtime

using System.Threading.Channels;
using WebFuzzer.Core.Filters;
using WebFuzzer.Core.Http;
using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Engine;

/// <summary>
/// FuzzEngine với UI callbacks — dùng cho WPF
/// Thêm partial class để không sửa FuzzEngine.cs gốc
/// </summary>
public partial class FuzzEngine
{
    private readonly Action<FuzzResult>? _onResult;
    private readonly Action<long, string>? _onProgress;
    private readonly Action<string>? _onTerminalLine;

    /// <summary>
    /// Constructor cho WPF UI — nhận callbacks thay vì ConsoleReporter
    /// </summary>
    public FuzzEngine(
        FuzzOptions options,
        Action<FuzzResult> onResult,
        Action<long, string> onProgress,
        Action<string> onTerminalLine)
    {
        _options        = options;
        _filter         = new ResponseFilter(options);
        _reporter       = new SilentReporter(); // không in ra console
        _onResult       = onResult;
        _onProgress     = onProgress;
        _onTerminalLine = onTerminalLine;
    }

    /// <summary>
    /// RunAsync với CancellationToken từ UI
    /// </summary>
    public async Task RunAsync(CancellationToken ct)
    {
        _onTerminalLine?.Invoke($"[WebFuzzer] Target: {_options.Url}");
        _onTerminalLine?.Invoke($"[WebFuzzer] Wordlist: {_options.Wordlist}");
        _onTerminalLine?.Invoke($"[WebFuzzer] Threads: {_options.Threads}");

        var httpClientFactory = new FuzzHttpClientFactory(_options);
        using var httpClient  = httpClientFactory.Create();

        if (_options.AutoCalibrate)
        {
            _onTerminalLine?.Invoke("[WebFuzzer] Auto-calibrating...");
            await RunAutoCalibrationAsync(httpClient, ct);
        }

        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(_options.Threads * 2)
        {
            FullMode = BoundedChannelFullMode.Wait
        });

        var startTime = DateTime.UtcNow;

        var producer = Task.Run(async () =>
        {
            await foreach (var word in WordlistReader.ReadAsync(_options.Wordlist, ct))
                await channel.Writer.WriteAsync(word, ct);
            channel.Writer.Complete();
        }, ct);

        var workers = Enumerable.Range(0, _options.Threads)
            .Select(_ => ProcessWorkerUI(channel.Reader, httpClient, ct))
            .ToArray();

        await Task.WhenAll(workers.Append(producer));

        var duration = DateTime.UtcNow - startTime;
        _onTerminalLine?.Invoke($"[WebFuzzer] Completed: {_requestCount} requests in {duration:mm\\:ss\\.fff}");
        _onTerminalLine?.Invoke($"[WebFuzzer] Matches: {_matchCount}");
    }

    private async Task ProcessWorkerUI(
        ChannelReader<string> reader,
        HttpClient httpClient,
        CancellationToken ct)
    {
        await foreach (var word in reader.ReadAllAsync(ct))
        {
            try
            {
                var request   = RequestBuilder.Build(_options, word);
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                using var response = await httpClient.SendAsync(request, ct);
                stopwatch.Stop();

                var body = await response.Content.ReadAsStringAsync(ct);

                var needsBody = !string.IsNullOrEmpty(_options.MatchRegex)
                             || !string.IsNullOrEmpty(_options.FilterRegex)
                             || _options.Verbose;

                var result = new FuzzResult
                {
                    Word          = word,
                    Url           = request.RequestUri!.ToString(),
                    StatusCode    = (int)response.StatusCode,
                    ContentLength = body.Length,
                    WordCount     = CountWords(body),
                    LineCount     = CountLines(body),
                    DurationMs    = stopwatch.ElapsedMilliseconds,
                    ResponseBody  = needsBody ? body : null
                };

                Interlocked.Increment(ref _requestCount);
                _onProgress?.Invoke(_requestCount, word);

                if (_filter.IsMatch(result))
                {
                    Interlocked.Increment(ref _matchCount);
                    _onResult?.Invoke(result);        // → UI DataGrid
                    _onTerminalLine?.Invoke(
                        $"[{result.StatusCode}] {result.Word,-40} Size:{result.ContentLength,-8} Words:{result.WordCount,-6} {result.Url}");
                }
            }
            catch (OperationCanceledException) { break; }
            catch (HttpRequestException ex)
            {
                if (_options.Verbose)
                    _onTerminalLine?.Invoke($"[ERR] {word}: {ex.Message}");
            }
        }
    }

    private async Task RunAutoCalibrationAsync(HttpClient httpClient, CancellationToken ct)
    {
        var probeSizes      = new List<int>();
        var probeWordCounts = new List<int>();
        var probeLines      = new List<int>();

        foreach (var _ in Enumerable.Range(0, 3))
        {
            try
            {
                var probe   = Guid.NewGuid().ToString("N");
                var request = RequestBuilder.Build(_options, probe);
                using var response = await httpClient.SendAsync(request, ct);
                var body = await response.Content.ReadAsStringAsync(ct);
                probeSizes.Add(body.Length);
                probeWordCounts.Add(CountWords(body));
                probeLines.Add(CountLines(body));
            }
            catch { }
        }

        bool hasRegex = !string.IsNullOrEmpty(_options.MatchRegex);

        if (probeSizes.Distinct().Count() == 1 && !hasRegex)
        {
            _options.FilterSize ??= new HashSet<int>();
            _options.FilterSize.Add(probeSizes[0]);
            _onTerminalLine?.Invoke($"[Calibration] Auto-filtering Size: {probeSizes[0]}");
        }
        if (probeWordCounts.Distinct().Count() == 1 && !hasRegex)
        {
            _options.FilterWords ??= new HashSet<int>();
            _options.FilterWords.Add(probeWordCounts[0]);
            _onTerminalLine?.Invoke($"[Calibration] Auto-filtering Words: {probeWordCounts[0]}");
        }
        if (probeLines.Distinct().Count() == 1 && !hasRegex)
        {
            _options.FilterLines ??= new HashSet<int>();
            _options.FilterLines.Add(probeLines[0]);
            _onTerminalLine?.Invoke($"[Calibration] Auto-filtering Lines: {probeLines[0]}");
        }
    }
}

/// <summary>
/// Reporter rỗng — dùng khi UI tự handle output
/// </summary>
public class SilentReporter : WebFuzzer.Core.Output.ConsoleReporter
{
    public SilentReporter() : base(new FuzzOptions { Silent = true }) { }
}