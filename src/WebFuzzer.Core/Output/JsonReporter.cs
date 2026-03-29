using System.Text;
using Newtonsoft.Json;
using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Output;

/// <summary>
/// Xuất kết quả ra file JSON.
/// </summary>
public class JsonReporter : IFuzzReporter
{
    private readonly string _filePath;
    private readonly List<FuzzResult> _results = new();
    private readonly object _lock = new();

    public JsonReporter(string filePath)
    {
        _filePath = filePath;
    }

    public Task InitAsync() => Task.CompletedTask;

    public Task ReportAsync(FuzzResult result)
    {
        lock (_lock)
            _results.Add(result);
        return Task.CompletedTask;
    }

    public async Task FinalizeAsync()
    {
        var json = JsonConvert.SerializeObject(_results, Formatting.Indented);
        await File.WriteAllTextAsync(_filePath, json, Encoding.UTF8);
        Console.WriteLine($"[JSON] Đã xuất {_results.Count} kết quả → {_filePath}");
    }
}
