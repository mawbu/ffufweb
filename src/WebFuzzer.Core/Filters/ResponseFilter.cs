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
    /// </summary>
    public FilterEvalResult Evaluate(FuzzResult result)
    {
        var body = result.ResponseBody ?? "";

        // ==========================================
        // KHỐI 1: STRICT RULES (LUẬT CỨNG)
        // Nếu vi phạm khối này, result KHÔNG ĐƯỢC PHÉP báo cáo
        // (Bao gồm cả việc Detection cũng không được quyền cứu)
        // ==========================================

        // 1. FilterRegex — loại bỏ tuyệt đối nếu body khớp (-fr)
        if (_filterRegex != null)
        {
            try
            {
                if (_filterRegex.IsMatch(body)) return new FilterEvalResult { IsBlockedByStrictRule = true };
            }
            catch (RegexMatchTimeoutException) { /* timeout → bỏ qua */ }
        }

        // 2. Filter status code — loại bỏ nếu user chỉ định (-fc)
        if (_filterCodes?.Contains(result.StatusCode) == true)
        {
            return new FilterEvalResult { IsBlockedByStrictRule = true };
        }

        // 3. MatchRegex — nếu có cờ -mr, body PHẢI chứa pattern
        bool regexMatched = false;
        if (_matchRegex != null)
        {
            try
            {
                if (!_matchRegex.IsMatch(body)) 
                {
                    // Body không chứa Regex -> vi phạm Strict Rule
                    return new FilterEvalResult { IsBlockedByStrictRule = true };
                }
                regexMatched = true; // ✅ Mạch chứa Regex -> Bypass Soft filter về size/words
            }
            catch (RegexMatchTimeoutException) 
            { 
                return new FilterEvalResult { IsBlockedByStrictRule = true }; 
            }
        }

        // Nếu vượt qua khối 1, nó không bị cấm
        var eval = new FilterEvalResult { IsBlockedByStrictRule = false, IsPassedBySoftRule = true };

        // ==========================================
        // KHỐI 2: SOFT RULES (LUẬT MỀM)
        // Nếu vi phạm, mặc định sẽ ẩn khỏi kết quả (IsPassedBySoftRule = false)
        // NHƯNG Detection có quyền can thiệp và kéo nó lại (RetainedByDetection)
        // ==========================================

        // 4. Match status codes mặc định (-mc mặc định 200, 301, 302 v.v)
        if (_matchCodes != null && !_matchCodes.Contains(result.StatusCode)) 
        {
            eval = new FilterEvalResult { IsBlockedByStrictRule = false, IsPassedBySoftRule = false };
        }

        // 5. Size/Words/Lines filter (kế thừa từ Auto-Calibration hoặc cờ filter thông thường)
        // Chỉ áp dụng khi KHÔNG có MatchRegex
        if (!regexMatched && eval.IsPassedBySoftRule)
        {
            if (_options.FilterSize?.Contains(result.ContentLength) == true) eval = new FilterEvalResult { IsPassedBySoftRule = false };
            else if (_options.FilterWords?.Contains(result.WordCount) == true) eval = new FilterEvalResult { IsPassedBySoftRule = false };
            else if (_options.FilterLines?.Contains(result.LineCount) == true) eval = new FilterEvalResult { IsPassedBySoftRule = false };
            else if (_options.MatchSize != null && !_options.MatchSize.Contains(result.ContentLength)) eval = new FilterEvalResult { IsPassedBySoftRule = false };
            else if (_options.MatchWords != null && !_options.MatchWords.Contains(result.WordCount)) eval = new FilterEvalResult { IsPassedBySoftRule = false };
            else if (_options.MatchLines != null && !_options.MatchLines.Contains(result.LineCount)) eval = new FilterEvalResult { IsPassedBySoftRule = false };
        }

        return eval;
    }

    public bool NeedsResponseBody =>
        _matchRegex != null || _filterRegex != null || _options.Verbose;
}