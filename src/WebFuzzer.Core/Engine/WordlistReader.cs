namespace WebFuzzer.Core.Engine;

public static class WordlistReader
{
    public static async IAsyncEnumerable<string> ReadAsync(
        string path,
        [System.Runtime.CompilerServices.EnumeratorCancellation]
        CancellationToken ct = default)
    {
        // ✅ FIX: Mở file với FileShare.Delete — cho phép File.Delete() được gọi
        //      trong khi file vẫn đang được đọc (tránh "being used by another process")
        TextReader reader = path == "-"
            ? Console.In
            : new StreamReader(
                new FileStream(path, FileMode.Open, FileAccess.Read,
                               FileShare.Read | FileShare.Delete));

        await using var disposable = reader as IAsyncDisposable;

        while (await reader.ReadLineAsync(ct) is { } line)
        {
            var word = line.Trim();
            if (!string.IsNullOrEmpty(word) && !word.StartsWith('#'))
                yield return word;
        }
    }
}