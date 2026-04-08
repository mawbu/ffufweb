using System.CommandLine;
using WebFuzzer.Core.Detection;
using WebFuzzer.Core.Engine;
using WebFuzzer.Core.Models;

var urlOption = new Option<string>(
    aliases: new[] { "--url", "-u" },
    description: "Target URL (use FUZZ as the placeholder)")
{ IsRequired = true };

var wordlistOption = new Option<string>(
    aliases: new[] { "--wordlist", "-w" },
    description: "Path to wordlist file")
{ IsRequired = true };

var threadsOption = new Option<int>(
    aliases: new[] { "--threads", "-t" },
    getDefaultValue: () => 40,
    description: "Number of concurrent threads");

// ── Match options ────────────────────────────────────────────────────────────
var matchCodesOption = new Option<string[]>(
    aliases: new[] { "--match-code", "-mc" },
    getDefaultValue: () => new[] { "200", "301", "302" },
    description: "Match HTTP status codes (e.g. 200,301,302)")
{ AllowMultipleArgumentsPerToken = true };

var matchRegexOption = new Option<string>(
    aliases: new[] { "--match-regex", "-mr" },
    description: "Match responses containing this regex (e.g. \"admin|password\")");

var matchSizeOption = new Option<string>(
    aliases: new[] { "--match-size", "-ms" },
    description: "Match response size in bytes (e.g. 1234 or 100,200,300)");

var matchWordsOption = new Option<string>(
    aliases: new[] { "--match-words", "-mw" },
    description: "Match response word count (e.g. 50)");

var matchLinesOption = new Option<string>(
    aliases: new[] { "--match-lines", "-ml" },
    description: "Match response line count (e.g. 10)");

// ── Filter options ───────────────────────────────────────────────────────────
var filterCodesOption = new Option<string[]>(
    aliases: new[] { "--filter-code", "-fc" },
    description: "Filter HTTP status codes (e.g. 404,403)")
{ AllowMultipleArgumentsPerToken = true };

var filterRegexOption = new Option<string>(
    aliases: new[] { "--filter-regex", "-fr" },
    description: "Filter out responses matching this regex (e.g. \"Not Found|Error\")");

var filterSizeOption = new Option<string>(
    aliases: new[] { "--filter-size", "-fs" },
    description: "Filter responses by size in bytes (e.g. 416 or 100,200,416)");

var filterWordsOption = new Option<string>(
    aliases: new[] { "--filter-words", "-fw" },
    description: "Filter responses by word count (e.g. 31)");

var filterLinesOption = new Option<string>(
    aliases: new[] { "--filter-lines", "-fl" },
    description: "Filter responses by line count (e.g. 16)");

// ── Request options ──────────────────────────────────────────────────────────
var headersOption = new Option<string[]>(
    aliases: new[] { "--header", "-H" },
    description: "Custom headers (format: 'Name: Value')")
{ AllowMultipleArgumentsPerToken = true };

var methodOption = new Option<string>(
    aliases: new[] { "--method", "-X" },
    getDefaultValue: () => "GET",
    description: "HTTP method");

var dataOption = new Option<string>(
    aliases: new[] { "--data", "-d" },
    description: "Request body data (use FUZZ as placeholder)");

// ── Output options ───────────────────────────────────────────────────────────
var outputOption = new Option<string>(
    aliases: new[] { "--output", "-o" },
    description: "Output file path");

var formatOption = new Option<string>(
    aliases: new[] { "--output-format", "-of" },
    getDefaultValue: () => "json",
    description: "Output format: json|csv");

var silentOption = new Option<bool>(
    aliases: new[] { "--silent", "-s" },
    description: "Silent mode (suppress banner/progress)");

var verboseOption = new Option<bool>(
    aliases: new[] { "--verbose", "-v" },
    description: "Verbose mode (show response body preview)");

// ── Misc options ─────────────────────────────────────────────────────────────
var proxyOption = new Option<string>(
    aliases: new[] { "--proxy", "-x" },
    description: "Proxy URL (e.g. http://127.0.0.1:8080)");

var timeoutOption = new Option<int>(
    aliases: new[] { "--timeout" },
    getDefaultValue: () => 10,
    description: "Timeout in seconds per request");

var rateOption = new Option<int>(
    aliases: new[] { "--rate" },
    getDefaultValue: () => 0,
    description: "Rate limit (req/sec, 0 = unlimited)");

var autoCalibrateOption = new Option<bool>(
    aliases: new[] { "--auto-calibrate", "-ac" },
    description: "Auto-detect and filter catch-all responses");

// ── Detection options ──────────────────────────────────────────────
var detectOption = new Option<bool>(
    aliases: new[] { "--detect" },
    description: "Enable Smart Detection — run VulnerabilityDetector before filter to catch 500/error responses");

var detectThresholdOption = new Option<string>(
    aliases: new[] { "--detect-threshold" },
    getDefaultValue: () => "likely",
    description: "Detection bypass threshold: suspicious (score>=15) | likely (score>=40, default) | confirmed (score>=70)");
    
var detectConfirmOption = new Option<bool>(
    aliases: new[] { "--confirm" },
    description: "Enable Auto-Retest confirmation logic");

// ── Root command ─────────────────────────────────────────────────────────────
var rootCommand = new RootCommand("WebFuzzer - Web fuzzing tool inspired by ffuf");

// Match
rootCommand.AddOption(urlOption);
rootCommand.AddOption(wordlistOption);
rootCommand.AddOption(threadsOption);
rootCommand.AddOption(matchCodesOption);
rootCommand.AddOption(matchRegexOption);
rootCommand.AddOption(matchSizeOption);
rootCommand.AddOption(matchWordsOption);
rootCommand.AddOption(matchLinesOption);
// Filter
rootCommand.AddOption(filterCodesOption);
rootCommand.AddOption(filterRegexOption);
rootCommand.AddOption(filterSizeOption);
rootCommand.AddOption(filterWordsOption);
rootCommand.AddOption(filterLinesOption);
// Request
rootCommand.AddOption(headersOption);
rootCommand.AddOption(methodOption);
rootCommand.AddOption(dataOption);
// Output
rootCommand.AddOption(outputOption);
rootCommand.AddOption(formatOption);
rootCommand.AddOption(silentOption);
rootCommand.AddOption(verboseOption);
// Misc
rootCommand.AddOption(proxyOption);
rootCommand.AddOption(timeoutOption);
rootCommand.AddOption(rateOption);
rootCommand.AddOption(autoCalibrateOption);
// Detection
rootCommand.AddOption(detectOption);
rootCommand.AddOption(detectThresholdOption);
rootCommand.AddOption(detectConfirmOption);

rootCommand.SetHandler(async (context) =>
{
    // Helper: parse "416" hoặc "100,200,416" → HashSet<int>
    static HashSet<int>? ParseIntSet(string? raw) =>
        raw == null ? null :
        raw.Split(',', StringSplitOptions.RemoveEmptyEntries)
           .Select(s => int.Parse(s.Trim()))
           .ToHashSet();

    var options = new FuzzOptions
    {
        Url            = context.ParseResult.GetValueForOption(urlOption)!,
        Wordlist       = context.ParseResult.GetValueForOption(wordlistOption)!,
        Threads        = context.ParseResult.GetValueForOption(threadsOption),

        // Match
        MatchCodes     = context.ParseResult.GetValueForOption(matchCodesOption),
        MatchRegex     = context.ParseResult.GetValueForOption(matchRegexOption),
        MatchSize      = ParseIntSet(context.ParseResult.GetValueForOption(matchSizeOption)),
        MatchWords     = ParseIntSet(context.ParseResult.GetValueForOption(matchWordsOption)),
        MatchLines     = ParseIntSet(context.ParseResult.GetValueForOption(matchLinesOption)),

        // Filter
        FilterCodes    = context.ParseResult.GetValueForOption(filterCodesOption),
        FilterRegex    = context.ParseResult.GetValueForOption(filterRegexOption),
        FilterSize     = ParseIntSet(context.ParseResult.GetValueForOption(filterSizeOption)),
        FilterWords    = ParseIntSet(context.ParseResult.GetValueForOption(filterWordsOption)),
        FilterLines    = ParseIntSet(context.ParseResult.GetValueForOption(filterLinesOption)),

        // Request
        Headers        = context.ParseResult.GetValueForOption(headersOption),
        Method         = context.ParseResult.GetValueForOption(methodOption)!,
        Data           = context.ParseResult.GetValueForOption(dataOption),

        // Output
        OutputFile     = context.ParseResult.GetValueForOption(outputOption),
        OutputFormat   = context.ParseResult.GetValueForOption(formatOption)!,
        Silent         = context.ParseResult.GetValueForOption(silentOption),
        Verbose        = context.ParseResult.GetValueForOption(verboseOption),

        // Misc
        Proxy          = context.ParseResult.GetValueForOption(proxyOption),
        TimeoutSeconds = context.ParseResult.GetValueForOption(timeoutOption),
        RateLimit      = context.ParseResult.GetValueForOption(rateOption),
        AutoCalibrate  = context.ParseResult.GetValueForOption(autoCalibrateOption),

        // Smart Detection
        EnableDetection = context.ParseResult.GetValueForOption(detectOption),
        DetectionBypassThreshold = (context.ParseResult.GetValueForOption(detectThresholdOption) ?? "likely") switch
        {
            "suspicious" => Severity.Suspicious,
            "confirmed"  => Severity.Confirmed,
            _            => Severity.Likely  // default
        },
        EnableConfirmation = context.ParseResult.GetValueForOption(detectConfirmOption),
    };

    var engine = new FuzzEngine(options);
    await engine.RunAsync();
});

return await rootCommand.InvokeAsync(args);