using System.ComponentModel;
using System.Runtime.CompilerServices;
using WebFuzzer.Core.Detection;
using WebFuzzer.Core.Models;

namespace WebFuzzer.UI.ViewModels;

/// <summary>
/// ViewModel bọc FuzzResult + DetectionResult để bind vào DataGrid.
/// Tách biệt UI khỏi Core model — FuzzResult không cần biết về Detection.
/// </summary>
public sealed class FuzzResultViewModel : INotifyPropertyChanged
{
    private DetectionResult _detection = DetectionResult.None;

    // ── Wrap FuzzResult (pass-through) ───────────────────────────────────────
    public FuzzResult Result { get; }

    public int    StatusCode    => Result.StatusCode;
    public string Word          => Result.Word ?? "";

    /// <summary>
    /// ✅ FIX: Payload SQL — hiển thị rõ payload đã gửi (alias của Word, nhưng tách cột riêng trong DataGrid)
    /// </summary>
    public string Payload       => Result.Payload ?? Result.Word ?? "";

    /// <summary>
    /// ✅ FIX: URL thực tế có payload nhúng vào — không còn bị trống
    /// </summary>
    public string Url           => Result.Url ?? "";

    public int    ContentLength => Result.ContentLength;
    public int    WordCount     => Result.WordCount;
    public int    LineCount     => Result.LineCount;
    public long   DurationMs    => Result.DurationMs;
    public string ResponseBody  => Result.ResponseBody ?? "";
    public string InjectedBody  => Result.InjectedBody ?? "";
    public string MatchReason   => Result.MatchReason ?? "";
    public string? VulnType     => Result.DetectedVulnType;
    public string? Confirmation => Result.ConfirmationSummary;
    public bool   IsVerified    => !string.IsNullOrEmpty(Result.ConfirmationSummary)
                                   && Result.ConfirmationSummary.Contains("[VERIFIED]");

    /// <summary>
    /// ✅ MỚI: Màu status code để bind style trong DataGrid
    /// </summary>
    public string StatusCategory => Result.StatusCode switch
    {
        >= 500 => "ServerError",
        >= 400 => "ClientError",
        >= 300 => "Redirect",
        >= 200 => "Success",
        _      => "Unknown"
    };

    // ── Detection (có thể update sau khi baseline sẵn sàng) ─────────────────
    public DetectionResult Detection
    {
        get => _detection;
        set
        {
            _detection = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ConfidenceLabel));
            OnPropertyChanged(nameof(HasAlert));
            OnPropertyChanged(nameof(RowSeverity));
        }
    }

    /// <summary>Text hiển thị trong cột Confidence, ví dụ: "🔴 85%"</summary>
    public string ConfidenceLabel => _detection.ShortLabel;

    /// <summary>True nếu severity >= Suspicious — dùng để highlight row</summary>
    public bool HasAlert => _detection.Severity >= Severity.Suspicious;

    /// <summary>Severity string để DataTrigger bind trong XAML</summary>
    public string RowSeverity => _detection.Severity.ToString();

    public FuzzResultViewModel(FuzzResult result)
    {
        Result = result;
    }

    // ── INotifyPropertyChanged ───────────────────────────────────────────────
    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
