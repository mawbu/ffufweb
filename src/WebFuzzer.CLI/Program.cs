using System.CommandLine;
using WebFuzzer.Core.Engine;
using WebFuzzer.Core.Models;

var urlOption      = new Option<string>(["--url", "-u"], "Target URL (use FUZZ as the placeholder)") { IsRequired = true };
var wordlistOption = new Option<string>(["--wordlist", "-w"], "Path to wordlist file") { IsRequired = true };
var threadsOption  = new Option<int>(["--threads", "-t"], () => 40, "Number of concurrent threads");
var matchCodesOption = new Option<string[]>(["--mc"], () => ["200", "301", "302"], "Match HTTP status codes")
    { AllowMultipleArgumentsPerToken = true };
var filterCodesOption = new Option<string[]>(["--fc"], "Filter HTTP status codes")
    { AllowMultipleArgumentsPerToken = true };
var headersOption  = new Option<string[]>(["--header", "-H"], "Custom headers (format: 'Name: Value')")
    { AllowMultipleArgumentsPerToken = true };
var methodOption   = new Option<string>(["--method", "-X"], () => "GET", "HTTP method");
var outputOption   = new Option<string>(["--output", "-o"], "Output file path");
var formatOption   = new Option<string>(["--output-format", "-of"], () => "json", "Output format: json|csv");
var silentOption   = new Option<bool>(["--silent", "-s"], "Silent mode (suppress banner/progress)");
var verboseOption  = new Option<bool>(["--verbose", "-v"], "Verbose mode");
var proxyOption    = new Option<string>(["--proxy", "-x"], "Proxy URL (e.g. http://127.0.0.1:8080)");
var timeoutOption  = new Option<int>(["--timeout"], () => 10, "Timeout in seconds per request");
var rateOption     = new Option<int>(["--rate"], () => 0, "Rate limit (req/sec, 0 = unlimited)");

var rootCommand = new RootCommand("WebFuzzer - Web fuzzing tool inspired by ffuf")
{
    urlOption, wordlistOption, threadsOption,
    matchCodesOption, filterCodesOption,
    headersOption, methodOption,
    outputOption, formatOption,
    silentOption, verboseOption,
    proxyOption, timeoutOption, rateOption
};

rootCommand.SetHandler(async (context) =>
{
    var options = new FuzzOptions
    {
        Url           = context.ParseResult.GetValueForOption(urlOption)!,
        Wordlist      = context.ParseResult.GetValueForOption(wordlistOption)!,
        Threads       = context.ParseResult.GetValueForOption(threadsOption),
        MatchCodes    = context.ParseResult.GetValueForOption(matchCodesOption),
        FilterCodes   = context.ParseResult.GetValueForOption(filterCodesOption),
        Headers       = context.ParseResult.GetValueForOption(headersOption),
        Method        = context.ParseResult.GetValueForOption(methodOption)!,
        OutputFile    = context.ParseResult.GetValueForOption(outputOption),
        OutputFormat  = context.ParseResult.GetValueForOption(formatOption)!,
        Silent        = context.ParseResult.GetValueForOption(silentOption),
        Verbose       = context.ParseResult.GetValueForOption(verboseOption),
        Proxy         = context.ParseResult.GetValueForOption(proxyOption),
        TimeoutSeconds = context.ParseResult.GetValueForOption(timeoutOption),
        RateLimit     = context.ParseResult.GetValueForOption(rateOption),
    };

    var engine = new FuzzEngine(options);
    await engine.RunAsync();
});

return await rootCommand.InvokeAsync(args);