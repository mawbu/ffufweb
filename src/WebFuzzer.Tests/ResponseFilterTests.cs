using WebFuzzer.Core.Filters;
using WebFuzzer.Core.Models;
using Xunit;

namespace WebFuzzer.Tests;

public class ResponseFilterTests
{
    private static FuzzResult MakeResult(int status, int size = 100, int words = 10, int lines = 5) =>
        new FuzzResult
        {
            StatusCode    = status,
            ContentLength = size,
            WordCount     = words,
            LineCount     = lines,
            Word          = "test",
            Url           = "http://example.com/test"
        };

    [Fact]
    public void NoRules_AllowsEverything()
    {
        // MatchCodes = null means no match filtering — all pass
        var options = new FuzzOptions { MatchCodes = null };
        var filter  = new ResponseFilter(options);

        Assert.True(filter.IsMatch(MakeResult(200)));
        Assert.True(filter.IsMatch(MakeResult(404)));
        Assert.True(filter.IsMatch(MakeResult(500)));
    }

    [Fact]
    public void FilterStatusCode_Hides404()
    {
        var options = new FuzzOptions { MatchCodes = null, FilterCodes = ["404"] };
        var filter  = new ResponseFilter(options);

        Assert.False(filter.IsMatch(MakeResult(404)));
        Assert.True(filter.IsMatch(MakeResult(200)));
    }

    [Fact]
    public void MatchStatusCode_OnlyShows200()
    {
        var options = new FuzzOptions { MatchCodes = ["200"] };
        var filter  = new ResponseFilter(options);

        Assert.True(filter.IsMatch(MakeResult(200)));
        Assert.False(filter.IsMatch(MakeResult(403)));
        Assert.False(filter.IsMatch(MakeResult(404)));
    }

    [Fact]
    public void FilterSize_HidesMatchingSize()
    {
        var options = new FuzzOptions { MatchCodes = null, FilterSize = new HashSet<int> { 100 } };
        var filter  = new ResponseFilter(options);

        Assert.False(filter.IsMatch(MakeResult(200, size: 100)));
        Assert.True(filter.IsMatch(MakeResult(200, size: 200)));
    }

    [Fact]
    public void FilterWords_HidesMatchingWordCount()
    {
        var options = new FuzzOptions { MatchCodes = null, FilterWords = new HashSet<int> { 10 } };
        var filter  = new ResponseFilter(options);

        Assert.False(filter.IsMatch(MakeResult(200, words: 10)));
        Assert.True(filter.IsMatch(MakeResult(200, words: 50)));
    }

    [Fact]
    public void FilterLines_HidesMatchingLineCount()
    {
        var options = new FuzzOptions { MatchCodes = null, FilterLines = new HashSet<int> { 5 } };
        var filter  = new ResponseFilter(options);

        Assert.False(filter.IsMatch(MakeResult(200, lines: 5)));
        Assert.True(filter.IsMatch(MakeResult(200, lines: 20)));
    }

    [Fact]
    public void CombinedMatchAndFilter_FilterTakesPriority()
    {
        // MatchCode=200 AND FilterCode=200 → should be hidden (filter applied first)
        var options = new FuzzOptions
        {
            MatchCodes  = ["200"],
            FilterCodes = ["200"]
        };
        var filter = new ResponseFilter(options);

        // FilterCode removes it before MatchCode can accept it
        Assert.False(filter.IsMatch(MakeResult(200)));
    }
}
