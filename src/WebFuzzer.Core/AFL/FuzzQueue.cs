using System.Collections.Concurrent;

namespace WebFuzzer.Core.AFL;

/// <summary>
/// Corpus Entry — đại diện cho một payload trong FuzzQueue.
/// Mang theo metadata: thế hệ mutation, payload cha, và energy score.
/// </summary>
public sealed class CorpusEntry
{
    /// <summary>Payload string sẽ được gửi trong request.</summary>
    public string Payload { get; init; } = "";

    /// <summary>
    /// Thế hệ mutation:
    ///   - 0 = seed gốc từ wordlist
    ///   - 1 = mutation trực tiếp từ seed
    ///   - 2 = mutation của mutation
    ///   - N = ...
    /// Khi Generation >= MaxMutationDepth → không enqueue lại nữa,
    /// ngăn corpus bùng nổ theo cấp số nhân.
    /// </summary>
    public int MutationGeneration { get; init; } = 0;

    /// <summary>
    /// Payload cha đã sinh ra entry này qua mutation.
    /// null nếu là seed gốc từ wordlist.
    /// Dùng để trace lineage: admin → admin' → admin' OR 1=1
    /// </summary>
    public string? ParentPayload { get; init; }

    /// <summary>
    /// Energy score — số fingerprints mới mà seed gốc đã tạo ra.
    /// Energy cao → Mutator sinh ra nhiều biến thể hơn.
    /// Mặc định = 1 cho initial seeds.
    /// </summary>
    public int Energy { get; set; } = 1;
}

/// <summary>
/// Thread-safe FuzzQueue quản lý Corpus Entries cho evolutionary fuzzing.
/// Dùng ConcurrentQueue<CorpusEntry> làm backing store.
/// Enforces MaxMutationDepth — không enqueue entries vượt quá giới hạn.
/// </summary>
public sealed class FuzzQueue
{
    private readonly ConcurrentQueue<CorpusEntry> _queue = new();
    private readonly int _maxMutationDepth;
    private long _totalEnqueued;
    private long _totalDropped; // bị reject do depth limit

    public FuzzQueue(int maxMutationDepth = 5)
    {
        _maxMutationDepth = maxMutationDepth;
    }

    /// <summary>Số entries hiện tại trong queue.</summary>
    public int Count => _queue.Count;

    /// <summary>Queue có rỗng không.</summary>
    public bool IsEmpty => _queue.IsEmpty;

    /// <summary>Tổng số entries đã enqueue thành công (bao gồm đã dequeue).</summary>
    public long TotalEnqueued => Interlocked.Read(ref _totalEnqueued);

    /// <summary>Tổng số entries bị reject do vượt MaxMutationDepth.</summary>
    public long TotalDropped => Interlocked.Read(ref _totalDropped);

    /// <summary>
    /// Enqueue một CorpusEntry. Sẽ bị reject nếu MutationGeneration >= MaxMutationDepth.
    /// Thread-safe.
    /// </summary>
    /// <returns>true nếu enqueue thành công, false nếu bị reject do depth limit.</returns>
    public bool Enqueue(CorpusEntry entry)
    {
        if (entry.MutationGeneration >= _maxMutationDepth)
        {
            Interlocked.Increment(ref _totalDropped);
            return false;
        }

        _queue.Enqueue(entry);
        Interlocked.Increment(ref _totalEnqueued);
        return true;
    }

    /// <summary>
    /// Nạp initial seeds từ wordlist. Tất cả có Generation = 0, ParentPayload = null.
    /// </summary>
    public void EnqueueInitialSeeds(IEnumerable<string> seeds)
    {
        foreach (var seed in seeds)
        {
            _queue.Enqueue(new CorpusEntry
            {
                Payload = seed,
                MutationGeneration = 0,
                ParentPayload = null,
                Energy = 1
            });
            Interlocked.Increment(ref _totalEnqueued);
        }
    }

    /// <summary>
    /// Thử dequeue một entry. Thread-safe.
    /// </summary>
    public bool TryDequeue(out CorpusEntry? entry)
    {
        return _queue.TryDequeue(out entry);
    }
}
