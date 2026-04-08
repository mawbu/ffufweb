namespace WebFuzzer.Core.Models;

public readonly struct FilterEvalResult
{
    public bool IsBlockedByStrictRule { get; init; }
    public bool IsPassedBySoftRule { get; init; }
}
