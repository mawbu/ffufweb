// FuzzEngine.UI.cs — Overload constructor cho WPF UI
// Thêm file này vào WebFuzzer.Core/Engine/
// FuzzEngine nhận thêm callbacks để update UI realtime

using System.Threading.Channels;
using WebFuzzer.Core.AFL;
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
    private readonly VulnerabilityConfirmer? _uiConfirmer;
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
        _uiConfirmer    = detector != null ? new VulnerabilityConfirmer(detector) : null;
        _uiBypassThreshold = options.DetectionBypassThreshold;

        if (options.EnableGrayBox)
        {
            _fingerprint = new BehavioralFingerprint();
            _fuzzQueue = new FuzzQueue(options.MaxMutationDepth);
            _mutator = new Mutator();
        }
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

        if (_options.EnableGrayBox)
            _onTerminalLine?.Invoke($"[AFL] Gray-Box mode ENABLED | MaxDepth={_options.MaxMutationDepth}");

        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(_options.Threads * 2)
        {
            FullMode = BoundedChannelFullMode.Wait
        });

        var startTime = DateTime.UtcNow;

        var producer = Task.Run(async () =>
        {
            try
            {
                await foreach (var word in WordlistReader.ReadAsync(_options.Wordlist, ct))
                    await channel.Writer.WriteAsync(word, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _onTerminalLine?.Invoke($"[ERROR] Failed to read wordlist: {ex.Message}");
            }
            finally
            {
                channel.Writer.Complete();
            }
        }, ct);

        Task[] workers;
        if (_options.EnableGrayBox)
        {
            workers = Enumerable.Range(0, _options.Threads)
                .Select(_ => ProcessWorkerUIGrayBox(channel.Reader, httpClient, ct))
                .ToArray();
        }
        else
        {
            workers = Enumerable.Range(0, _options.Threads)
                .Select(_ => ProcessWorkerUI(channel.Reader, httpClient, ct))
                .ToArray();
        }

        await Task.WhenAll(workers.Append(producer));

        var duration = DateTime.UtcNow - startTime;
        _onTerminalLine?.Invoke($"[WebFuzzer] Completed: {_requestCount} requests in {duration:mm\\:ss\\.fff}");
        _onTerminalLine?.Invoke($"[WebFuzzer] Matches: {_matchCount}");
        if (_bypassCount > 0)
            _onTerminalLine?.Invoke($"[Detection] {_bypassCount} bypass (filter would have dropped these)");
        if (_options.EnableGrayBox)
        {
            _onTerminalLine?.Invoke($"[AFL] Fingerprints: {_fingerprint!.TotalFingerprints} | Corpus: {_corpusCount} | Mutations: {_mutationCount}");
            if (_fuzzQueue!.TotalDropped > 0)
                _onTerminalLine?.Invoke($"[AFL] Dropped (depth limit): {_fuzzQueue.TotalDropped}");
        }
    }

    private async Task ProcessWorkerUI(
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

                var body = await response.Content.ReadAsStringAsync(ct);

                var needsBody = _options.EnableDetection
                             || !string.IsNullOrEmpty(_options.MatchRegex)
                             || !string.IsNullOrEmpty(_options.FilterRegex)
                             || _options.Verbose;

                // ✅ FIX: Lưu URL thực tế (đã có payload nhúng vào) từ request đã build
                var actualUrl = request.RequestUri?.ToString() ?? _options.Url;

                // Tính InjectedBody nếu có POST data chứa FUZZ
                string? injectedBody = null;
                if (!string.IsNullOrEmpty(_options.Data) && _options.Data.Contains("FUZZ"))
                    injectedBody = _options.Data.Replace("FUZZ", word);

                var result = new FuzzResult
                {
                    Word          = word,
                    Payload       = word,
                    Url           = actualUrl,
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

                // ── YÊU CẦU 2: Chạy Detection ─────────────────────────────────────
                bool isHighSeverity = false;
                if (_options.EnableDetection && _uiDetector?.IsReady == true)
                {
                    if (result.ResponseBody == null) result.ResponseBody = body;
                    
                    // ✅ FIX: Pass hasAuth to detector so IDOR context is correct
                    bool hasAuth = (_options.Headers != null && _options.Headers.Any(h => h.Trim().StartsWith("Authorization", StringComparison.OrdinalIgnoreCase))) ||
                                  !string.IsNullOrEmpty(_options.Cookie);

                    var detection = _uiDetector.Analyze(result, word, hasAuth, _options.Method);

                    result.DetectionScore   = detection.ConfidenceScore;
                    result.DetectedVulnType = detection.PrimaryVulnType.ToString();
                    result.DetectionSummary = detection.Summary;

                    isHighSeverity = detection.Severity >= _uiBypassThreshold;
                }

                // ── YÊU CẦU 3: Quyết định Report ─────────────────────────────────
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
                    if (_uiConfirmer != null && result.DetectionScore >= 40)
                    {
                        var confirmation = await _uiConfirmer.VerifyAsync(result, _options, httpClient);
                        result.ConfirmationSummary = confirmation.Reason;
                        
                        if (confirmation.IsConfirmed)
                        {
                            Interlocked.Increment(ref _confirmedCount);
                            result.DetectionSummary = "✅ [VERIFIED] " + result.DetectionSummary;
                        }
                        else
                        {
                            // Nếu không xác thực được, hạ mức độ tin cậy
                            result.DetectionSummary = "⚠️ [UNVERIFIED] " + result.DetectionSummary;
                            result.DetectionScore = 40; // Downgrade score since verification failed
                            if (result.MatchReason.StartsWith("DetectionBypass") && !_options.Silent)
                            {
                                // Remove Bypass badge if downgraded
                                result.MatchReason = "Downgraded";
                                result.IsRetainedByDetection = false;
                            }
                        }
                    }

                    Interlocked.Increment(ref _matchCount);
                    if (retainedByDetection) Interlocked.Increment(ref _bypassCount);
                    _onResult?.Invoke(result);        // → UI DataGrid

                    // ✅ FIX: Log cả Payload và URL thực tế
                    _onTerminalLine?.Invoke(
                        $"{(retainedByDetection ? "🔥 VULN " : "✅ MATCH ")} " +
                        $"[{result.StatusCode}] " +
                        $"Payload: {result.Payload,-35} " +
                        $"Size:{result.ContentLength,-8} " +
                        $"URL: {result.Url}");
                }
            }
            catch (OperationCanceledException) 
            { 
                if (ct.IsCancellationRequested) break;
                else
                {
                    if (_options.Verbose) _onTerminalLine?.Invoke($"[ERR] {word}: Request timed out (>{_options.TimeoutSeconds}s)");
                    continue;
                }
            }
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

        if (_uiDetector != null && probeResponses.Count > 0)
        {
            _uiDetector.SetBaseline(probeResponses);
            _onTerminalLine?.Invoke($"[Detection] AutoCal baseline ready from {probeResponses.Count} 2xx probe(s).");
        }
    }

    // ── Gray-Box Worker (UI) ─────────────────────────────────────────────────
    private async Task ProcessWorkerUIGrayBox(
        ChannelReader<string> reader,
        HttpClient httpClient,
        CancellationToken ct)
    {
        Interlocked.Increment(ref _activeWorkers);
        int seedCounter = 0;

        try
        {
            while (!ct.IsCancellationRequested)
            {
                string? word = null;
                int mutationGeneration = 0;
                string? parentPayload = null;

                // Round-robin 3:1: Channel trước, FuzzQueue sau
                bool tryMutation = seedCounter >= 3 && _fuzzQueue != null && !_fuzzQueue.IsEmpty;

                if (tryMutation && _fuzzQueue!.TryDequeue(out var entry) && entry != null)
                {
                    word = entry.Payload;
                    mutationGeneration = entry.MutationGeneration;
                    parentPayload = entry.ParentPayload;
                    seedCounter = 0;
                }
                else if (reader.TryRead(out var channelWord))
                {
                    word = channelWord;
                    seedCounter++;
                }
                else if (reader.Completion.IsCompleted)
                {
                    if (_isFinished) break;

                    if (_fuzzQueue != null && _fuzzQueue.TryDequeue(out var fallbackEntry) && fallbackEntry != null)
                    {
                        word = fallbackEntry.Payload;
                        mutationGeneration = fallbackEntry.MutationGeneration;
                        parentPayload = fallbackEntry.ParentPayload;
                    }
                    else
                    {
                        Interlocked.Increment(ref _idleWorkers);
                        if (Interlocked.Read(ref _idleWorkers) == Interlocked.Read(ref _activeWorkers) && (_fuzzQueue?.IsEmpty ?? true))
                        {
                            _isFinished = true; // Báo hiệu tất cả workers dừng
                            break;
                        }
                        
                        // Chờ xem có worker nào khác push vào queue không
                        while (!_isFinished && (_fuzzQueue?.IsEmpty ?? true) && !ct.IsCancellationRequested)
                        {
                            await Task.Delay(50, ct);
                        }

                        Interlocked.Decrement(ref _idleWorkers);
                        if (_isFinished) break;
                        continue;
                    }
                }
                else
                {
                    try { await reader.WaitToReadAsync(ct); }
                    catch (OperationCanceledException) { break; }
                    continue;
                }

                if (word == null) continue;
                if (word.Contains("__TIME__"))
                    word = word.Replace("__TIME__", "3");

                try
                {
                    var request   = RequestBuilder.Build(_options, word);
                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                    using var response = await httpClient.SendAsync(request, ct);
                    stopwatch.Stop();

                    var body = await response.Content.ReadAsStringAsync(ct);
                    var needsBody = _options.EnableDetection
                                 || !string.IsNullOrEmpty(_options.MatchRegex)
                                 || !string.IsNullOrEmpty(_options.FilterRegex)
                                 || _options.Verbose;

                    var actualUrl = request.RequestUri?.ToString() ?? _options.Url;
                    string? injectedBody = null;
                    if (!string.IsNullOrEmpty(_options.Data) && _options.Data.Contains("FUZZ"))
                        injectedBody = _options.Data.Replace("FUZZ", word);

                    var result = new FuzzResult
                    {
                        Word              = word,
                        Payload           = word,
                        Url               = actualUrl,
                        InjectedBody      = injectedBody,
                        StatusCode        = (int)response.StatusCode,
                        ContentLength     = body.Length,
                        WordCount         = CountWords(body),
                        LineCount         = CountLines(body),
                        DurationMs        = stopwatch.ElapsedMilliseconds,
                        ResponseBody      = needsBody ? body : null,
                        Timestamp         = DateTime.UtcNow,
                        MutationGeneration = mutationGeneration,
                        ParentPayload     = parentPayload
                    };

                    Interlocked.Increment(ref _requestCount);
                    _onProgress?.Invoke(_requestCount, word);

                    // ── AFL: Behavioral Fingerprint ──────────────────────────
                    if (_fingerprint!.IsNewFingerprint(result.StatusCode, result.ContentLength, result.DurationMs))
                    {
                        Interlocked.Increment(ref _corpusCount);
                        var fp = BehavioralFingerprint.ComputeFingerprint(
                            result.StatusCode, result.ContentLength, result.DurationMs);

                        _onTerminalLine?.Invoke($"[NEW PATH] Fingerprint: {fp} | Payload: {word} | Gen: {mutationGeneration}");

                        var mutations = _mutator!.Mutate(word, 1, mutationGeneration);
                        int mutEnqueued = 0;
                        foreach (var mut in mutations)
                        {
                            if (_fuzzQueue!.Enqueue(mut))
                            {
                                Interlocked.Increment(ref _mutationCount);
                                mutEnqueued++;
                            }
                        }
                        if (mutEnqueued > 0)
                            _onTerminalLine?.Invoke($"[MUTATION] +{mutEnqueued} variants from \"{word}\" (Gen {mutationGeneration} → {mutationGeneration + 1})");
                    }

                    if (_options.Verbose)
                    {
                        var preview = body.Length > 80 ? body[..80].Replace('\n', ' ') + "…" : body.Replace('\n', ' ');
                        _onTerminalLine?.Invoke(
                            $"[{(int)response.StatusCode}] {word,-25} Size:{body.Length,-8} → {preview}");
                    }

                    // ── Filter + Detection (giữ logic cũ) ────────────────────
                    var filterEval = _filter.Evaluate(result);
                    if (filterEval.IsBlockedByStrictRule) continue;

                    bool isHighSeverity = false;
                    if (_options.EnableDetection && _uiDetector?.IsReady == true)
                    {
                        if (result.ResponseBody == null) result.ResponseBody = body;
                        bool hasAuth = (_options.Headers != null && _options.Headers.Any(h => h.Trim().StartsWith("Authorization", StringComparison.OrdinalIgnoreCase))) ||
                                      !string.IsNullOrEmpty(_options.Cookie);

                        var detection = _uiDetector.Analyze(result, word, hasAuth, _options.Method);
                        result.DetectionScore   = detection.ConfidenceScore;
                        result.DetectedVulnType = detection.PrimaryVulnType.ToString();
                        result.DetectionSummary = detection.Summary;
                        isHighSeverity = detection.Severity >= _uiBypassThreshold;
                    }

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
                        if (_uiConfirmer != null && result.DetectionScore >= 40)
                        {
                            var confirmation = await _uiConfirmer.VerifyAsync(result, _options, httpClient);
                            result.ConfirmationSummary = confirmation.Reason;
                            if (confirmation.IsConfirmed)
                            {
                                Interlocked.Increment(ref _confirmedCount);
                                result.DetectionSummary = "✅ [VERIFIED] " + result.DetectionSummary;
                            }
                            else
                            {
                                result.DetectionSummary = "⚠️ [UNVERIFIED] " + result.DetectionSummary;
                                result.DetectionScore = 40;
                                if (result.MatchReason != null && result.MatchReason.StartsWith("DetectionBypass"))
                                {
                                    result.MatchReason = "Downgraded";
                                    result.IsRetainedByDetection = false;
                                }
                            }
                        }

                        Interlocked.Increment(ref _matchCount);
                        if (retainedByDetection) Interlocked.Increment(ref _bypassCount);
                        _onResult?.Invoke(result);

                        _onTerminalLine?.Invoke(
                            $"{(retainedByDetection ? "🔥 VULN " : "✅ MATCH ")} " +
                            $"[{result.StatusCode}] " +
                            $"Payload: {result.Payload,-35} " +
                            $"Size:{result.ContentLength,-8} " +
                            $"{(mutationGeneration > 0 ? $"🧬Gen{mutationGeneration} " : "")}" +
                            $"URL: {result.Url}");
                    }
                }
                catch (OperationCanceledException) 
                { 
                    if (ct.IsCancellationRequested) break;
                    else
                    {
                        if (_options.Verbose) _onTerminalLine?.Invoke($"[ERR] {word}: Request timed out (>{_options.TimeoutSeconds}s)");
                        continue;
                    }
                }
                catch (HttpRequestException ex)
                {
                    if (_options.Verbose)
                        _onTerminalLine?.Invoke($"[ERR] {word}: {ex.Message}");
                }
            }
        }
        finally
        {
            Interlocked.Decrement(ref _activeWorkers);
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
