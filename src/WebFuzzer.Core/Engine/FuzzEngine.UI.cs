// FuzzEngine.UI.cs — Overload constructor cho WPF UI
// Thêm file này vào WebFuzzer.Core/Engine/
// FuzzEngine nhận thêm callbacks để update UI realtime

using System.Threading.Channels;
using WebFuzzer.Core.Detection;
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

    // Detection — được inject từ UI; nếu null = detection tắt
    private readonly VulnerabilityDetector? _uiDetector;
    private readonly Severity _uiBypassThreshold;

    /// <summary>
    /// Constructor cho WPF UI — nhận callbacks + optional detector
    /// </summary>
    public FuzzEngine(
        FuzzOptions options,
        Action<FuzzResult> onResult,
        Action<long, string> onProgress,
        Action<string> onTerminalLine,
        VulnerabilityDetector? detector = null)
    {
        _options        = options;
        _filter         = new ResponseFilter(options);
        _reporter       = new SilentReporter(); // không in ra console
        _onResult       = onResult;
        _onProgress     = onProgress;
        _onTerminalLine = onTerminalLine;
        _uiDetector     = detector;
        _uiBypassThreshold = options.DetectionBypassThreshold;
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
        if (_bypassCount > 0)
            _onTerminalLine?.Invoke($"[Detection] {_bypassCount} bypass (filter would have dropped these)");
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

                // needsBody: thêm EnableDetection — detector cần body trước khi quyết định bypass
                var needsBody = _options.EnableDetection
                             || !string.IsNullOrEmpty(_options.MatchRegex)
                             || !string.IsNullOrEmpty(_options.FilterRegex)
                             || _options.Verbose;

                var result = new FuzzResult
                {
                    Word          = word,
                    Payload       = word,
                    Url           = request.RequestUri!.ToString(),
                    StatusCode    = (int)response.StatusCode,
                    ContentLength = body.Length,
                    WordCount     = CountWords(body),
                    LineCount     = CountLines(body),
                    DurationMs    = stopwatch.ElapsedMilliseconds,
                    ResponseBody  = needsBody ? body : null,
                    Timestamp     = DateTime.UtcNow
                };

                Interlocked.Increment(ref _requestCount);
                _onProgress?.Invoke(_requestCount, word);

                // Debug mode (Verbose): hiển thị TẤT CẢ response
                if (_options.Verbose)
                {
                    var preview = body.Length > 80 ? body[..80].Replace('\n', ' ') + "…" : body.Replace('\n', ' ');
                    _onTerminalLine?.Invoke(
                        $"[{(int)response.StatusCode}] {word,-25} Size:{body.Length,-8} → {preview}");
                }

                // ── YÊU CẦU 1: Kiểm tra Strict Filter ─────────────────────────────
                var filterEval = _filter.Evaluate(result);
                if (filterEval.IsBlockedByStrictRule) continue; 

                // ── YÊU CẦU 2: Chạy Detection (chỉ chạy nếu không bị strict block) ─────
                bool isHighSeverity = false;
                if (_options.EnableDetection && _uiDetector?.IsReady == true)
                {
                    if (result.ResponseBody == null) result.ResponseBody = body;
                    var detection = _uiDetector.Analyze(result, word);

                    result.DetectionScore = detection.ConfidenceScore;
                    result.DetectedVulnType = detection.PrimaryVulnType.ToString();
                    result.DetectionSummary = detection.Summary;

                    isHighSeverity = detection.Severity >= _uiBypassThreshold;
                }

                // ── YÊU CẦU 3: Quyết định Report ────────────────────────────────
                bool retainedByDetection = false;
                if (!filterEval.IsPassedBySoftRule && isHighSeverity)
                {
                    retainedByDetection = true;
                    result.IsRetainedByDetection = true;
                }

                if (filterEval.IsPassedBySoftRule || retainedByDetection)
                {
                    Interlocked.Increment(ref _matchCount);
                    if (retainedByDetection) Interlocked.Increment(ref _bypassCount);
                    _onResult?.Invoke(result);        // → UI DataGrid
                    _onTerminalLine?.Invoke(
                        $"{(retainedByDetection ? "🔥 VULN " : "✅ MATCH ")} [{result.StatusCode}] {result.Word,-40} Size:{result.ContentLength,-8} Words:{result.WordCount,-6} {result.Url}");
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
        var probeResponses  = new List<FuzzResult>(); // chỉ 2xx probes cho baseline

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

                // Guard: chỉ dùng 2xx cho baseline — 500 sẽ skew timing/size
                int statusCode = (int)response.StatusCode;
                if (statusCode >= 200 && statusCode < 300)
                {
                    probeResponses.Add(new FuzzResult
                    {
                        Word = probe, StatusCode = statusCode,
                        ContentLength = body.Length, WordCount = CountWords(body),
                        LineCount = CountLines(body), DurationMs = 0,
                        ResponseBody = body, Timestamp = DateTime.UtcNow
                    });
                }
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

        // Setup baseline cho detector (chỉ dùng 2xx — 5xx sẽ skew baseline)
        if (_uiDetector != null && probeResponses.Count > 0)
        {
            _uiDetector.SetBaseline(probeResponses);
            _onTerminalLine?.Invoke($"[Detection] AutoCal baseline ready from {probeResponses.Count} 2xx probe(s).");
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