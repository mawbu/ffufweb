using System.Threading.Channels;
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
    private long _requestCount = 0;
    private long _matchCount   = 0;

    public FuzzEngine(FuzzOptions options)
    {
        _options  = options;
        _filter   = new ResponseFilter(options);
        _reporter = new ConsoleReporter(options);
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
            }
            catch { }
        }

        if (probeSizes.Count == 0)
        {
            if (!_options.Silent)
                Console.WriteLine(":: Auto-calibration failed. Continuing without it.");
            return;
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
    }

    private async Task ProcessWorker(
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

                // Luôn đọc body — cần cho ContentLength, WordCount, LineCount
                var body = await response.Content.ReadAsStringAsync(ct);

                // Lưu body vào result chỉ khi cần cho regex hoặc verbose
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

                if (_filter.IsMatch(result))
                {
                    Interlocked.Increment(ref _matchCount);
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