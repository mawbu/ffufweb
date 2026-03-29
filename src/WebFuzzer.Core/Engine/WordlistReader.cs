namespace WebFuzzer.Core.Engine;

public static class WordlistReader
{
    public static async IAsyncEnumerable<string> ReadAsync(
        string path,
        [System.Runtime.CompilerServices.EnumeratorCancellation]
        CancellationToken ct = default)
    {
        // Đọc từ stdin nếu path là "-"
        TextReader reader = path == "-"
            ? Console.In
            : new StreamReader(path);

        await using var disposable = reader as IAsyncDisposable;

        while (await reader.ReadLineAsync(ct) is { } line)
        {
            var word = line.Trim();
            if (!string.IsNullOrEmpty(word) && !word.StartsWith('#'))
                yield return word;
        }
    }
}