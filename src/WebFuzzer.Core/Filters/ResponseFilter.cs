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

        _matchCodes = options.MatchCodes?
            .SelectMany(s => s.Split(',', StringSplitOptions.RemoveEmptyEntries))
            .Select(s => int.Parse(s.Trim()))
            .ToHashSet();

        _filterCodes = options.FilterCodes?
            .SelectMany(s => s.Split(',', StringSplitOptions.RemoveEmptyEntries))
            .Select(s => int.Parse(s.Trim()))
            .ToHashSet();

        var regexOptions = RegexOptions.IgnoreCase | RegexOptions.Compiled;
        var timeout      = TimeSpan.FromSeconds(1);

        _matchRegex  = options.MatchRegex  != null ? new Regex(options.MatchRegex,  regexOptions, timeout) : null;
        _filterRegex = options.FilterRegex != null ? new Regex(options.FilterRegex, regexOptions, timeout) : null;
    }

    /// <summary>
    /// Đánh giá FuzzResult theo 2 nhóm phân loại: Strict Rule (cứng) và Soft Rule (mềm).
    /// MatchReason được set để UI biết chính xác lý do result được hiển thị.
    /// </summary>
    public FilterEvalResult Evaluate(FuzzResult result)
    {
        var body = result.ResponseBody ?? "";

        // ==========================================
        // KHỐI 1: STRICT RULES (LUẬT CỨNG)
        // ==========================================

        // 1. FilterRegex — loại bỏ tuyệt đối nếu body khớp (-fr)
        if (_filterRegex != null)
        {
            try
            {
                if (_filterRegex.IsMatch(body))
                    return new FilterEvalResult { IsBlockedByStrictRule = true };
            }
            catch (RegexMatchTimeoutException) { }
        }

        // 2. Filter status code (-fc)
        if (_filterCodes?.Contains(result.StatusCode) == true)
            return new FilterEvalResult { IsBlockedByStrictRule = true };

        // 3. MatchRegex (-mr): body PHẢI chứa pattern — strict rule
        bool regexMatched = false;
        if (_matchRegex != null)
        {
            try
            {
                if (!_matchRegex.IsMatch(body))
                    return new FilterEvalResult { IsBlockedByStrictRule = true };

                regexMatched = true;
            }
            catch (RegexMatchTimeoutException)
            {
                return new FilterEvalResult { IsBlockedByStrictRule = true };
            }
        }

        // Nếu regex khớp → pass ngay với ByRegex, bỏ qua soft rules về size/words
        if (regexMatched)
        {
            return new FilterEvalResult
            {
                IsBlockedByStrictRule = false,
                IsPassedBySoftRule    = true,
                MatchReason           = MatchReason.ByRegex
            };
        }

        // ==========================================
        // KHỐI 2: SOFT RULES (LUẬT MỀM)
        // Detection có quyền override IsPassedBySoftRule = false
        // ==========================================

        // 4. Match status codes (-mc)
        if (_matchCodes != null && !_matchCodes.Contains(result.StatusCode))
        {
            return new FilterEvalResult
            {
                IsBlockedByStrictRule = false,
                IsPassedBySoftRule    = false,
                MatchReason           = MatchReason.None
            };
        }

        // 5. Size/Words/Lines filter (Auto-Calibration hoặc cờ filter thường)
        if (_options.FilterSize?.Contains(result.ContentLength) == true)
            return new FilterEvalResult { IsBlockedByStrictRule = false, IsPassedBySoftRule = false };
        if (_options.FilterWords?.Contains(result.WordCount) == true)
            return new FilterEvalResult { IsBlockedByStrictRule = false, IsPassedBySoftRule = false };
        if (_options.FilterLines?.Contains(result.LineCount) == true)
            return new FilterEvalResult { IsBlockedByStrictRule = false, IsPassedBySoftRule = false };

        // 6. Match size/words/lines (-ms/-mw/-ml)
        if (_options.MatchSize != null && !_options.MatchSize.Contains(result.ContentLength))
            return new FilterEvalResult { IsBlockedByStrictRule = false, IsPassedBySoftRule = false, MatchReason = MatchReason.BySize };
        if (_options.MatchWords != null && !_options.MatchWords.Contains(result.WordCount))
            return new FilterEvalResult { IsBlockedByStrictRule = false, IsPassedBySoftRule = false, MatchReason = MatchReason.ByWords };
        if (_options.MatchLines != null && !_options.MatchLines.Contains(result.LineCount))
            return new FilterEvalResult { IsBlockedByStrictRule = false, IsPassedBySoftRule = false, MatchReason = MatchReason.ByLines };

        // Xác định MatchReason cụ thể cho result pass
        var reason = MatchReason.ByStatusCode;
        if (_options.MatchSize  != null && _options.MatchSize.Contains(result.ContentLength))  reason = MatchReason.BySize;
        if (_options.MatchWords != null && _options.MatchWords.Contains(result.WordCount))      reason = MatchReason.ByWords;
        if (_options.MatchLines != null && _options.MatchLines.Contains(result.LineCount))      reason = MatchReason.ByLines;

        return new FilterEvalResult
        {
            IsBlockedByStrictRule = false,
            IsPassedBySoftRule    = true,
            MatchReason           = reason
        };
    }

    public bool NeedsResponseBody =>
        _matchRegex != null || _filterRegex != null || _options.Verbose;
}