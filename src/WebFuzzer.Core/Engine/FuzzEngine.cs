using System.Threading.Channels;
using WebFuzzer.Core.Detection;
using WebFuzzer.Core.Filters;
using WebFuzzer.Core.Http;
using WebFuzzer.Core.Models;
using WebFuzzer.Core.Output;

namespace WebFuzzer.Core.Engine;

public partial class FuzzEngine
{
    private readonly FuzzOptions _options;
    private readonly ResponseFilter _filter;
    private readonly ConsoleReporter _reporter;
    private readonly VulnerabilityDetector? _detector;
    private readonly VulnerabilityConfirmer? _confirmer;
    private long _requestCount = 0;
    private long _matchCount   = 0;
    private long _bypassCount  = 0; 
    private long _confirmedCount = 0; 

    public FuzzEngine(FuzzOptions options)
    {
        _options  = options;
        _filter   = new ResponseFilter(options);
        _reporter = new ConsoleReporter(options);
        
        if (options.EnableDetection)
        {
            _detector = new VulnerabilityDetector();
            _confirmer = new VulnerabilityConfirmer(_detector);
        }
    }

    public async Task RunAsync()
    {
        _reporter.PrintBanner(_options);

        var httpClientFactory = new FuzzHttpClientFactory(_options);
        using var httpClient  = httpClientFactory.Create();

        if (_options.AutoCalibrate)
            await RunAutoCalibrationAsync(httpClient);

        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(_options.Threads * 2)
        {
            FullMode = BoundedChannelFullMode.Wait
        });

        var startTime = DateTime.UtcNow;
        var cts = new CancellationTokenSource();

        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
            _reporter.PrintSummary(_requestCount, _matchCount, DateTime.UtcNow - startTime);
        };

        var producer = Task.Run(async () =>
        {
            try
            {
                await foreach (var word in WordlistReader.ReadAsync(_options.Wordlist, cts.Token))
                    await channel.Writer.WriteAsync(word, cts.Token);
            }
            catch (Exception ex)
            {
                if (!_options.Silent)
                    Console.WriteLine($"\n[ERROR] Failed to read wordlist: {ex.Message}");
                cts.Cancel(); // Cancel workers if input fails
            }
            finally
            {
                channel.Writer.Complete();
            }
        }, cts.Token);

        var workers = Enumerable.Range(0, _options.Threads)
            .Select(_ => ProcessWorker(channel.Reader, httpClient, cts.Token))
            .ToArray();

        await Task.WhenAll(workers.Append(producer));
        _reporter.PrintSummary(_requestCount, _matchCount, DateTime.UtcNow - startTime);

        if (_bypassCount > 0 && !_options.Silent)
            Console.WriteLine($":: [Detection] {_bypassCount} result(s) bypass filter due to detection score.");

        if (_options.OutputFile != null)
            await _reporter.SaveAsync(_options.OutputFile);
    }

    private async Task RunAutoCalibrationAsync(HttpClient httpClient)
    {
        if (!_options.Silent)
            Console.WriteLine(":: Auto-calibrating... (sending 3 random probe requests)");

        var probeSizes      = new List<int>();
        var probeWordCounts = new List<int>();
        var probeLines      = new List<int>();
        var probeResponses  = new List<FuzzResult>(); // 2xx probes để thiết lập baseline detector

        foreach (var _ in Enumerable.Range(0, 3))
        {
            try
            {
                var probe   = Guid.NewGuid().ToString("N");
                var request = RequestBuilder.Build(_options, probe);
                using var response = await httpClient.SendAsync(request);
                var body = await response.Content.ReadAsStringAsync();
                probeSizes.Add(body.Length);
                probeWordCounts.Add(CountWords(body));
                probeLines.Add(CountLines(body));

                // Guard: chỉ dùng 2xx cho baseline detector — 500 sẽ skew timing/size
                int statusCode = (int)response.StatusCode;
                if (statusCode >= 200 && statusCode < 300)
                {
                    probeResponses.Add(new FuzzResult
                    {
                        Word          = probe,
                        StatusCode    = statusCode,
                        ContentLength = body.Length,
                        WordCount     = CountWords(body),
                        LineCount     = CountLines(body),
                        DurationMs    = 0,
                        ResponseBody  = body,
                        Timestamp     = DateTime.UtcNow
                    });
                }
            }
            catch { }
        }

        if (probeSizes.Count == 0)
        {
            if (!_options.Silent)
                Console.WriteLine(":: [Calibration] Failed: No responses received. Check your connection.");
            return;
        }

        // Cảnh báo nếu không có 2xx mẫu nào (thường do lỗi Auth)
        if (probeResponses.Count == 0 && !_options.Silent)
        {
            var firstStatus = probeSizes.Count > 0 ? "Non-2xx" : "N/A";
            Console.WriteLine($":: [Detection] ⚠ Baseline FAILED: No 2xx response from probes.");
            Console.WriteLine($":: [Detection] ⚠ This usually means your Token is expired or the Header is malformed.");
            Console.WriteLine($":: [Detection] ⚠ Detection engine will be DISABLED for this run.");
        }

        // ✅ Khi có MatchRegex: bỏ qua filter size/words/lines từ calibration
        // vì regex sẽ là bộ lọc chính, filter size sẽ chặn kết quả đúng
        bool hasRegex = !string.IsNullOrEmpty(_options.MatchRegex);

        if (probeSizes.Distinct().Count() == 1)
        {
            if (!hasRegex)
            {
                _options.FilterSize ??= new HashSet<int>();
                _options.FilterSize.Add(probeSizes[0]);
                if (!_options.Silent)
                    Console.WriteLine($":: [Calibration] Auto-filtering Size: {probeSizes[0]}");
            }
            else if (!_options.Silent)
                Console.WriteLine($":: [Calibration] Catch-all Size: {probeSizes[0]} (skipped — regex mode)");
        }

        if (probeWordCounts.Distinct().Count() == 1)
        {
            if (!hasRegex)
            {
                _options.FilterWords ??= new HashSet<int>();
                _options.FilterWords.Add(probeWordCounts[0]);
                if (!_options.Silent)
                    Console.WriteLine($":: [Calibration] Auto-filtering Words: {probeWordCounts[0]}");
            }
        }

        if (probeLines.Distinct().Count() == 1)
        {
            if (!hasRegex)
            {
                _options.FilterLines ??= new HashSet<int>();
                _options.FilterLines.Add(probeLines[0]);
                if (!_options.Silent)
                    Console.WriteLine($":: [Calibration] Auto-filtering Lines: {probeLines[0]}");
            }
        }

        if (!_options.Silent)
            Console.WriteLine("________________________________________________");

        // Setup baseline cho detector (chỉ dùng 2xx probes — 5xx sẽ skew baseline)
        if (_detector != null && probeResponses.Count > 0)
        {
            _detector.SetBaseline(probeResponses);
            if (!_options.Silent)
                Console.WriteLine($":: [Detection] Baseline ready from {probeResponses.Count} 2xx probe(s).");
        }
    }

    private async Task ProcessWorker(
        ChannelReader<string> reader,
        HttpClient httpClient,
        CancellationToken ct)
    {
        await foreach (var rawWord in reader.ReadAllAsync(ct))
        {
            string word = rawWord;
            if (word.Contains("__TIME__"))
            {
                word = word.Replace("__TIME__", "3");
            }

            try
            {
                var request   = RequestBuilder.Build(_options, word);
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                using var response = await httpClient.SendAsync(request, ct);
                stopwatch.Stop();

                // Đọc body: cần cho ContentLength, WordCount, LineCount.
                // Khi detection bật, cần body để chạy regex pattern — đọc luôn.
                var body = await response.Content.ReadAsStringAsync(ct);

                var needsBody = _options.EnableDetection        // ← detection cần body trước khi quyết định bypass
                             || !string.IsNullOrEmpty(_options.MatchRegex)
                             || !string.IsNullOrEmpty(_options.FilterRegex)
                             || _options.Verbose;

                // Tính InjectedBody nếu có POST data chứa FUZZ
                string? injectedBody = null;
                if (!string.IsNullOrEmpty(_options.Data) && _options.Data.Contains("FUZZ"))
                    injectedBody = _options.Data.Replace("FUZZ", word);

                var result = new FuzzResult
                {
                    Word          = word,
                    Payload       = word,
                    Url           = request.RequestUri!.ToString(),
                    InjectedBody  = injectedBody,
                    StatusCode    = (int)response.StatusCode,
                    ContentLength = body.Length,
                    WordCount     = CountWords(body),
                    LineCount     = CountLines(body),
                    DurationMs    = stopwatch.ElapsedMilliseconds,
                    ResponseBody  = needsBody ? body : null,
                    Timestamp     = DateTime.UtcNow
                };

                Interlocked.Increment(ref _requestCount);

                // ── YÊU CẦU 1: Kiểm tra Strict Filter ─────────────────────────────
                var filterEval = _filter.Evaluate(result);
                if (filterEval.IsBlockedByStrictRule)
                {
                    // Report progress if silent is off
                    if (!_options.Silent) _reporter.UpdateProgress(_requestCount, word);
                    continue;
                }

                // ── YÊU CẦU 2: Chạy Detection (chỉ chạy nếu không bị strict block) ─────
                bool isHighSeverity = false;
                if (_options.EnableDetection && _detector?.IsReady == true)
                {
                    if (result.ResponseBody == null) result.ResponseBody = body;
                    
                    // Kiểm tra xem request có chứa Authorization hoặc Cookie không để làm ngữ cảnh cho IDOR
                    bool hasAuth = (_options.Headers != null && _options.Headers.Any(h => h.Trim().StartsWith("Authorization", StringComparison.OrdinalIgnoreCase))) ||
                                  !string.IsNullOrEmpty(_options.Cookie);

                    var detection = _detector.Analyze(result, word, hasAuth, _options.Method);
                    
                    result.DetectionScore = detection.ConfidenceScore;
                    result.DetectedVulnType = detection.PrimaryVulnType.ToString();
                    result.DetectionSummary = detection.Summary;

                    isHighSeverity = detection.Severity >= _options.DetectionBypassThreshold;
                }

                // ── YÊU CẦU 3: Quyết định Report ────────────────────────────────
                bool retainedByDetection = false;
                if (!filterEval.IsPassedBySoftRule && isHighSeverity)
                {
                    retainedByDetection = true;
                    result.IsRetainedByDetection = true;
                    result.MatchReason = $"DetectionBypass (Score:{result.DetectionScore}, {result.DetectedVulnType})";
                }
                else if (filterEval.IsPassedBySoftRule)
                {
                    result.MatchReason = filterEval.MatchReason switch
                    {
                        MatchReason.ByStatusCode => "Status",
                        MatchReason.ByRegex => "Regex",
                        MatchReason.BySize => "Size",
                        MatchReason.ByWords => "Words",
                        MatchReason.ByLines => "Lines",
                        MatchReason.ByDetection => "Detection",
                        _ => "None"
                    };
                }

                if (filterEval.IsPassedBySoftRule || retainedByDetection)
                {
                    // ── [NEW] YÊU CẦU 4: Auto-Retest Confirmation ────────────────
                    if (_confirmer != null && result.DetectionScore >= 40)
                    {
                        var confirmation = await _confirmer.VerifyAsync(result, _options, httpClient);
                        result.ConfirmationSummary = confirmation.Reason;
                        
                        if (confirmation.IsConfirmed)
                        {
                            Interlocked.Increment(ref _confirmedCount);
                            // Highlight confirmed result
                            result.DetectionSummary = "✅ [VERIFIED] " + result.DetectionSummary;
                        }
                        else
                        {
                            // Nếu không xác thực được, hạ mức độ tin cậy
                            result.DetectionSummary = "⚠️ [UNVERIFIED] " + result.DetectionSummary;
                        }
                    }

                    Interlocked.Increment(ref _matchCount);
                    if (retainedByDetection) Interlocked.Increment(ref _bypassCount);
                    _reporter.PrintResult(result);
                }
                else if (!_options.Silent)
                {
                    _reporter.UpdateProgress(_requestCount, word);
                }
            }
            catch (HttpRequestException ex)
            {
                if (_options.Verbose)
                    _reporter.PrintError(word, ex.Message);
            }
        }
    }

    private static int CountWords(string text) =>
        text.Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries).Length;

    private static int CountLines(string text) =>
        text.Split('\n').Length;
}