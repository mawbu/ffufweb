using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Output;

/// <summary>
/// Interface chung cho tất cả reporters.
/// </summary>
public interface IFuzzReporter
{
    Task InitAsync();
    Task ReportAsync(FuzzResult result);
    Task FinalizeAsync();
}
