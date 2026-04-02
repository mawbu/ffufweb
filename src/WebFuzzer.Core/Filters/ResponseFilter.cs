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
    /// Thứ tự ưu tiên:
    ///   1. FilterRegex  — luôn loại bỏ nếu body khớp (cao nhất)
    ///   2. FilterCodes  — loại bỏ theo status code
    ///   3. MatchRegex   — nếu có, body PHẢI khớp; nếu khớp thì BYPASS filter size/words/lines
    ///   4. MatchCodes   — status code phải khớp
    ///   5. Size/Words/Lines filter — chỉ áp dụng khi KHÔNG có MatchRegex
    /// </summary>
    public bool IsMatch(FuzzResult result)
    {
        var body = result.ResponseBody ?? "";

        // ── Bước 1: FilterRegex — loại bỏ tuyệt đối nếu body khớp ──────────
        if (_filterRegex != null)
        {
            try   { if (_filterRegex.IsMatch(body)) return false; }
            catch (RegexMatchTimeoutException) { /* timeout → bỏ qua */ }
        }

        // ── Bước 2: Filter status code ───────────────────────────────────────
        if (_filterCodes?.Contains(result.StatusCode) == true) return false;

        // ── Bước 3: MatchRegex ───────────────────────────────────────────────
        // Nếu có -mr: body PHẢI chứa pattern
        // Nếu match → bypass filter Size/Words/Lines (vì đã tìm được nội dung)
        // Nếu không match → loại bỏ
        bool regexMatched = false;
        if (_matchRegex != null)
        {
            try
            {
                if (!_matchRegex.IsMatch(body)) return false;
                regexMatched = true; // ✅ match → bypass size/words/lines filter
            }
            catch (RegexMatchTimeoutException) { return false; }
        }

        // ── Bước 4: Match status codes ───────────────────────────────────────
        if (_matchCodes != null && !_matchCodes.Contains(result.StatusCode)) return false;

        // ── Bước 5: Size/Words/Lines filter ─────────────────────────────────
        // Chỉ áp dụng khi KHÔNG có MatchRegex
        // Lý do: khi dùng -mr, người dùng tìm theo nội dung body
        //        → filter size/words (từ auto-calibrate) không còn ý nghĩa
        if (!regexMatched)
        {
            if (_options.FilterSize?.Contains(result.ContentLength)  == true) return false;
            if (_options.FilterWords?.Contains(result.WordCount)      == true) return false;
            if (_options.FilterLines?.Contains(result.LineCount)      == true) return false;
            if (_options.MatchSize  != null && !_options.MatchSize.Contains(result.ContentLength))  return false;
            if (_options.MatchWords != null && !_options.MatchWords.Contains(result.WordCount))     return false;
            if (_options.MatchLines != null && !_options.MatchLines.Contains(result.LineCount))     return false;
        }

        return true;
    }

    public bool NeedsResponseBody =>
        _matchRegex != null || _filterRegex != null || _options.Verbose;
}