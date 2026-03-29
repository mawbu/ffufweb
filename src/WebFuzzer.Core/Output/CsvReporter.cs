using System.Globalization;
using CsvHelper;
using CsvHelper.Configuration;
using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Output;

/// <summary>
/// Xuất kết quả ra file CSV.
/// </summary>
public class CsvReporter : IFuzzReporter
{
    private readonly string _filePath;
    private StreamWriter? _writer;
    private CsvWriter?    _csv;
    private readonly object _lock = new();

    public CsvReporter(string filePath)
    {
        _filePath = filePath;
    }

    public async Task InitAsync()
    {
        _writer = new StreamWriter(_filePath, append: false, System.Text.Encoding.UTF8);
        var cfg = new CsvConfiguration(CultureInfo.InvariantCulture);
        _csv = new CsvWriter(_writer, cfg);

        // Ghi header
        _csv.WriteHeader<FuzzResultCsvMap>();
        await _csv.NextRecordAsync();
    }

    public async Task ReportAsync(FuzzResult result)
    {
        lock (_lock)
        {
            _csv!.WriteRecord(new FuzzResultCsvMap(result));
            _csv.NextRecord();
        }
        await Task.CompletedTask;
    }

    public async Task FinalizeAsync()
    {
        if (_csv != null)  await _csv.FlushAsync();
        if (_writer != null) await _writer.FlushAsync();
        _writer?.Dispose();
        Console.WriteLine($"[CSV] Đã xuất kết quả → {_filePath}");
    }

    /// <summary>Flat DTO để CsvHelper serialize.</summary>
    private record FuzzResultCsvMap(
        string Payload,
        string Url,
        int    StatusCode,
        long   ContentLength,
        int    WordCount,
        int    LineCount,
        long   DurationMs,
        string? ContentType,
        string? Error,
        bool   IsFiltered,
        DateTime Timestamp)
    {
        public FuzzResultCsvMap(FuzzResult r) : this(
            r.Payload, r.Url, r.StatusCode, r.ContentLength,
            r.WordCount, r.LineCount, r.DurationMs, r.ContentType,
            r.Error, r.IsFiltered, r.Timestamp) { }
    }
}
