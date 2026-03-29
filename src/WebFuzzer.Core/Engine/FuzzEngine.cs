using System.Threading.Channels;
using WebFuzzer.Core.Filters;
using WebFuzzer.Core.Http;
using WebFuzzer.Core.Models;
using WebFuzzer.Core.Output;

namespace WebFuzzer.Core.Engine;

public class FuzzEngine
{
    private readonly FuzzOptions _options;
    private readonly ResponseFilter _filter;
    private readonly ConsoleReporter _reporter;
    private long _requestCount = 0;
    private long _matchCount = 0;

    public FuzzEngine(FuzzOptions options)
    {
        _options = options;
        _filter = new ResponseFilter(options);
        _reporter = new ConsoleReporter(options);
    }

    public async Task RunAsync()
    {
        _reporter.PrintBanner(_options);

        var httpClientFactory = new FuzzHttpClientFactory(_options);
        using var httpClient = httpClientFactory.Create();

        // Channel-based producer/consumer pattern
        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(_options.Threads * 2)
        {
            FullMode = BoundedChannelFullMode.Wait
        });

        // Rate limiter
        using var rateLimiter = _options.RateLimit > 0
            ? new SemaphoreSlim(1, 1)
            : null;

        var startTime = DateTime.UtcNow;
        var cts = new CancellationTokenSource();

        // Console.CancelKeyPress để Ctrl+C graceful shutdown
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
            _reporter.PrintSummary(_requestCount, _matchCount, DateTime.UtcNow - startTime);
        };

        // Producer: đọc wordlist vào channel
        var producer = Task.Run(async () =>
        {
            await foreach (var word in WordlistReader.ReadAsync(_options.Wordlist, cts.Token))
            {
                await channel.Writer.WriteAsync(word, cts.Token);
            }
            channel.Writer.Complete();
        }, cts.Token);

        // Consumer: N workers xử lý song song
        var workers = Enumerable.Range(0, _options.Threads)
            .Select(_ => ProcessWorker(channel.Reader, httpClient, cts.Token))
            .ToArray();

        await Task.WhenAll(workers.Append(producer));

        _reporter.PrintSummary(_requestCount, _matchCount, DateTime.UtcNow - startTime);

        if (_options.OutputFile != null)
            await _reporter.SaveAsync(_options.OutputFile);
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
                var request = RequestBuilder.Build(_options, word);
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                
                using var response = await httpClient.SendAsync(request, ct);
                stopwatch.Stop();
                
                var body = await response.Content.ReadAsStringAsync(ct);
                var result = new FuzzResult
                {
                    Word = word,
                    Url = request.RequestUri!.ToString(),
                    StatusCode = (int)response.StatusCode,
                    ContentLength = body.Length,
                    WordCount = CountWords(body),
                    LineCount = CountLines(body),
                    DurationMs = stopwatch.ElapsedMilliseconds,
                    ResponseBody = _options.Verbose ? body : null
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
        text.Split([' ', '\t', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries).Length;

    private static int CountLines(string text) =>
        text.Split('\n').Length;
}