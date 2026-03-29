using System.Text.RegularExpressions;
using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Filters;

public class ResponseFilter
{
    private readonly FuzzOptions _options;
    private readonly HashSet<int>? _matchCodes;
    private readonly HashSet<int>? _filterCodes;
    private readonly Regex? _matchRegex;
    private readonly Regex? _filterRegex;

    public ResponseFilter(FuzzOptions options)
    {
        _options = options;
        _matchCodes = options.MatchCodes?.Select(int.Parse).ToHashSet();
        _filterCodes = options.FilterCodes?.Select(int.Parse).ToHashSet();
        _matchRegex = options.MatchRegex != null ? new Regex(options.MatchRegex) : null;
        _filterRegex = options.FilterRegex != null ? new Regex(options.FilterRegex) : null;
    }

    public bool IsMatch(FuzzResult result)
    {
        // Filter codes (loại bỏ trước)
        if (_filterCodes?.Contains(result.StatusCode) == true) return false;
        if (_options.FilterSize?.Contains(result.ContentLength) == true) return false;
        if (_options.FilterWords?.Contains(result.WordCount) == true) return false;
        if (_options.FilterLines?.Contains(result.LineCount) == true) return false;
        if (_filterRegex?.IsMatch(result.ResponseBody ?? "") == true) return false;

        // Match codes (chỉ giữ lại nếu khớp)
        if (_matchCodes != null && !_matchCodes.Contains(result.StatusCode)) return false;
        if (_options.MatchSize != null && !_options.MatchSize.Contains(result.ContentLength)) return false;
        if (_options.MatchWords != null && !_options.MatchWords.Contains(result.WordCount)) return false;
        if (_options.MatchLines != null && !_options.MatchLines.Contains(result.LineCount)) return false;
        if (_matchRegex != null && !_matchRegex.IsMatch(result.ResponseBody ?? "")) return false;

        return true;
    }
}