using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Microsoft.Win32;
using WebFuzzer.Core.Detection;
using WebFuzzer.Core.Engine;
using WebFuzzer.Core.Models;
using WebFuzzer.UI.ViewModels;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace WebFuzzer.UI
{
    public partial class MainWindow : FluentWindow
    {
        // ── State ────────────────────────────────────────────────────────────
        private CancellationTokenSource? _cts;
        private readonly ObservableCollection<FuzzResultViewModel> _results = new();
        private ICollectionView? _resultsView;
        private readonly Stopwatch _stopwatch = new();
        private long _requestCount;
        private long _matchCount;
        private long _vulnCount;
        private long _bypassCount;
        private long _confirmedCount;
        private System.Windows.Threading.DispatcherTimer? _statsTimer;

        // ── Status Count Badges ──────────────────────────────────────────────
        private long _cnt2xx;
        private long _cnt3xx;
        private long _cnt4xx;
        private long _cnt5xx;

        // ── Detection ────────────────────────────────────────────────────────
        private readonly VulnerabilityDetector _detector = new();
        private Severity _filterSeverity = Severity.Normal;

        // ✅ MỚI: Status filter state
        private int _filterStatusGroup = 0; // 0=All, 1=2xx, 2=3xx, 3=4xx, 4=5xx

        public MainWindow()
        {
            ApplicationThemeManager.Apply(ApplicationTheme.Dark);
            InitializeComponent();

            _resultsView = CollectionViewSource.GetDefaultView(_results);
            _resultsView.Filter = FilterResults; // ✅ FIX: Dùng filter kết hợp severity + status
            ResultsGrid.ItemsSource = _resultsView;

            // Mỗi khi thay đổi field → cập nhật command preview
            TxtUrl.TextChanged          += (s, e) => UpdateCommandPreview();
            TxtWordlist.TextChanged     += (s, e) => UpdateCommandPreview();
            TxtMatchCodes.TextChanged   += (s, e) => UpdateCommandPreview();
            TxtFilterCodes.TextChanged  += (s, e) => UpdateCommandPreview();
            TxtFilterSize.TextChanged   += (s, e) => UpdateCommandPreview();
            TxtMatchRegex.TextChanged   += (s, e) => UpdateCommandPreview();
            TxtFilterRegex.TextChanged  += (s, e) => UpdateCommandPreview();
            TxtThreads.TextChanged      += (s, e) => UpdateCommandPreview();
            TxtTimeout.TextChanged      += (s, e) => UpdateCommandPreview();
            TxtRate.TextChanged         += (s, e) => UpdateCommandPreview();
            TxtProxy.TextChanged        += (s, e) => UpdateCommandPreview();
            TxtHeader.TextChanged       += (s, e) => UpdateCommandPreview();
            TxtData.TextChanged         += (s, e) => UpdateCommandPreview();
            CmbMethod.SelectionChanged  += (s, e) => UpdateCommandPreview();
            ChkAutoCalibrate.Checked    += (s, e) => UpdateCommandPreview();
            ChkAutoCalibrate.Unchecked  += (s, e) => UpdateCommandPreview();
            ChkVerbose.Checked          += (s, e) => UpdateCommandPreview();
            ChkVerbose.Unchecked        += (s, e) => UpdateCommandPreview();

            _statsTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(500)
            };
            _statsTimer.Tick += UpdateStats;

            UpdateCommandPreview();
        }

        // ── Combined Filter (Severity + Status) ──────────────────────────────

        /// <summary>
        /// ✅ FIX: Filter kết hợp severity VÀ status code group.
        /// Thay thế FilterBySeverity cũ — giờ một hàm xử lý cả hai.
        /// </summary>
        private bool FilterResults(object obj)
        {
            if (obj is not FuzzResultViewModel vm) return false;

            // Severity filter
            bool passSeverity = _filterSeverity == Severity.Normal
                || vm.Detection.Severity >= _filterSeverity;

            // ✅ MỚI: Status code group filter
            bool passStatus = _filterStatusGroup switch
            {
                1 => vm.StatusCode >= 200 && vm.StatusCode < 300,
                2 => vm.StatusCode >= 300 && vm.StatusCode < 400,
                3 => vm.StatusCode >= 400 && vm.StatusCode < 500,
                4 => vm.StatusCode >= 500,
                _ => true
            };

            return passSeverity && passStatus;
        }

        private void CmbSeverityFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _filterSeverity = CmbSeverityFilter.SelectedIndex switch
            {
                1 => Severity.Confirmed,
                2 => Severity.Likely,
                3 => Severity.Suspicious,
                _ => Severity.Normal
            };
            _resultsView?.Refresh();
        }

        /// <summary>✅ MỚI: Filter theo status code group</summary>
        private void CmbStatusFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _filterStatusGroup = CmbStatusFilter.SelectedIndex; // 0=All,1=2xx,2=3xx,3=4xx,4=5xx
            _resultsView?.Refresh();
        }

        // ── SQL Wordlist Quick Selector ───────────────────────────────────────

        /// <summary>✅ MỚI: Chọn nhanh SQL wordlist từ ComboBox</summary>
        private void CmbSqlPayload_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CmbSqlPayload.SelectedItem is ComboBoxItem item
                && item.Tag is string path && !string.IsNullOrEmpty(path))
            {
                TxtWordlist.Text = path;
                UpdateCommandPreview();
            }
        }

        // ── IDOR Mode ─────────────────────────────────────────────────────────

        /// <summary>
        /// Auto-detect ID cuối trong URL (ví dụ: /api/Users/3 → /api/Users/FUZZ, id=3)
        /// Hỗ trợ: path segment cuối là số, hoặc query param ?id=N
        /// </summary>
        private static (string? fuzzedUrl, int detectedId) AutoDetectIdInUrl(string url)
        {
            // Thử match path segment cuối: /something/123 hoặc /something/123?...
            var pathMatch = System.Text.RegularExpressions.Regex.Match(
                url, @"(.*/)([0-9]+)(/|\?.*)?$");
            if (pathMatch.Success && int.TryParse(pathMatch.Groups[2].Value, out int pathId))
            {
                var fuzzed = pathMatch.Groups[1].Value + "FUZZ" + pathMatch.Groups[3].Value;
                return (fuzzed, pathId);
            }

            // Thử match query param: ?id=123 hoặc ?userId=123
            var queryMatch = System.Text.RegularExpressions.Regex.Match(
                url, @"([?&](?:id|userId|user_id|orderId|order_id|productId)=)([0-9]+)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (queryMatch.Success && int.TryParse(queryMatch.Groups[2].Value, out int queryId))
            {
                var fuzzed = url.Replace(queryMatch.Groups[2].Value, "FUZZ");
                return (fuzzed, queryId);
            }

            return (null, 0);
        }

        /// <summary>
        /// Tạo wordlist IDOR từ dải ID, lưu vào file temp.
        /// Nếu URL chưa có FUZZ → auto-detect ID và rewrite URL.
        /// </summary>
        private string? PrepareIdorWordlist()
        {
            if (ChkIdorMode.IsChecked != true) return null;

            // ✅ FIX: Auto-detect ID nếu URL chưa có FUZZ
            if (!TxtUrl.Text.Contains("FUZZ"))
            {
                var (fuzzedUrl, detectedId) = AutoDetectIdInUrl(TxtUrl.Text);
                if (fuzzedUrl != null)
                {
                    AppendTerminal($"[IDOR] Auto-detected ID={detectedId} → URL rewritten: {fuzzedUrl}");
                    TxtUrl.Text = fuzzedUrl;

                    // Nếu user chưa đổi range mặc định → tự điền range xung quanh ID đó
                    if (TxtIdorFrom.Text == "1" && TxtIdorTo.Text == "100")
                    {
                        TxtIdorFrom.Text = Math.Max(1, detectedId - 30).ToString();
                        TxtIdorTo.Text   = (detectedId + 30).ToString();
                        AppendTerminal($"[IDOR] Auto-range: {TxtIdorFrom.Text} → {TxtIdorTo.Text}");
                    }
                }
                else
                {
                    MessageBox.Show(
                        "Không tìm thấy ID trong URL.\n\n" +
                        "Hãy thêm FUZZ vào URL thủ công, ví dụ:\n" +
                        "  https://example.com/api/Users/FUZZ\n" +
                        "  https://example.com/order?id=FUZZ",
                        "IDOR Mode", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return null;
                }
            }

            if (!int.TryParse(TxtIdorFrom.Text, out int from) ||
                !int.TryParse(TxtIdorTo.Text, out int to) ||
                from > to)
            {
                MessageBox.Show("IDOR range không hợp lệ. Kiểm tra ID From và ID To.",
                    "IDOR Mode", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            // Tạo file temp với dải số
            var tempPath = Path.Combine(Path.GetTempPath(), $"webfuzzer_idor_{Guid.NewGuid():N}.txt");
            var lines = Enumerable.Range(from, to - from + 1).Select(i => i.ToString());
            File.WriteAllLines(tempPath, lines);

            AppendTerminal($"[IDOR] Generated {to - from + 1} IDs ({from} → {to}) → {tempPath}");
            return tempPath;
        }

        // ── Detail Panel ─────────────────────────────────────────────────────

        private void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ResultsGrid.SelectedItem is not FuzzResultViewModel vm)
            {
                DetailPanel.Visibility = Visibility.Collapsed;
                return;
            }

            var detection = vm.Detection;

            if (detection.Severity == Severity.Normal || detection.Signals.Count == 0)
            {
                DetailPanel.Visibility = Visibility.Collapsed;
                return;
            }

            TxtDetailSummary.Text = detection.Summary;

            if (vm.IsVerified)
            {
                BrdVerified.Visibility = Visibility.Visible;
                TxtConfirmation.Text = vm.Confirmation;
            }
            else
            {
                BrdVerified.Visibility = Visibility.Collapsed;
            }

            SignalList.ItemsSource = detection.Signals;
            DetailPanel.Visibility = Visibility.Visible;
        }

        private void CloseDetailPanel_Click(object sender, RoutedEventArgs e)
        {
            DetailPanel.Visibility = Visibility.Collapsed;
            ResultsGrid.SelectedItem = null;
        }

        // ── Error Preset ─────────────────────────────────────────────────────
        private void CmbErrorPreset_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CmbErrorPreset.SelectedItem is ComboBoxItem item
                && item.Tag is string pattern && !string.IsNullOrEmpty(pattern))
            {
                TxtMatchRegex.Text = pattern;
                UpdateCommandPreview();
            }
        }

        private void BtnPreset_Click(object sender, RoutedEventArgs e)
        {
            CmbErrorPreset.IsDropDownOpen = !CmbErrorPreset.IsDropDownOpen;
        }

        // ── Command Preview ──────────────────────────────────────────────────
        private void UpdateCommandPreview()
        {
            var sb = new StringBuilder("webfuzzer");

            if (!string.IsNullOrWhiteSpace(TxtUrl.Text))
                sb.Append($" -u {TxtUrl.Text}");
            if (!string.IsNullOrWhiteSpace(TxtWordlist.Text))
                sb.Append($" -w {TxtWordlist.Text}");

            var method = (CmbMethod.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "GET";
            if (method != "GET") sb.Append($" -X {method}");

            if (!string.IsNullOrWhiteSpace(TxtMatchCodes.Text) && TxtMatchCodes.Text != "200,301,302")
                sb.Append($" -mc {TxtMatchCodes.Text}");
            if (!string.IsNullOrWhiteSpace(TxtFilterCodes.Text))
                sb.Append($" -fc {TxtFilterCodes.Text}");
            if (!string.IsNullOrWhiteSpace(TxtFilterSize.Text))
                sb.Append($" -fs {TxtFilterSize.Text}");
            if (!string.IsNullOrWhiteSpace(TxtMatchRegex.Text))
                sb.Append($" -mr \"{TxtMatchRegex.Text}\"");
            if (!string.IsNullOrWhiteSpace(TxtFilterRegex.Text))
                sb.Append($" -fr \"{TxtFilterRegex.Text}\"");
            if (TxtThreads.Text != "40")
                sb.Append($" -t {TxtThreads.Text}");
            if (TxtTimeout.Text != "10")
                sb.Append($" --timeout {TxtTimeout.Text}");
            if (TxtRate.Text != "0")
                sb.Append($" --rate {TxtRate.Text}");
            if (!string.IsNullOrWhiteSpace(TxtProxy.Text))
                sb.Append($" -x {TxtProxy.Text}");
            if (!string.IsNullOrWhiteSpace(TxtHeader.Text))
                sb.Append($" -H \"{TxtHeader.Text.Replace("\r", "").Replace("\n", " ").Trim()}\"");
            if (!string.IsNullOrWhiteSpace(TxtData.Text))
                sb.Append($" -d \"{TxtData.Text.Replace("\r", "").Replace("\n", " ").Trim()}\"");
            if (ChkAutoCalibrate.IsChecked == true)
                sb.Append(" -ac");
            if (ChkSmartDetection.IsChecked == true)
                sb.Append(" --detect");
            if (ChkEnableConfirmation.IsChecked == true)
                sb.Append(" --confirm");
            if (ChkVerbose.IsChecked == true)
                sb.Append(" -v");
            if (ChkIdorMode.IsChecked == true)
                sb.Append($" --idor {TxtIdorFrom.Text}-{TxtIdorTo.Text}");

            TxtCommandPreview.Text = sb.ToString();
        }

        // ── Run ──────────────────────────────────────────────────────────────
        private async void BtnRun_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateInputs()) return;

            // ✅ MỚI: IDOR mode — override wordlist bằng dải ID
            string? idorTempFile = null;
            if (ChkIdorMode.IsChecked == true)
            {
                idorTempFile = PrepareIdorWordlist();
                if (idorTempFile == null) return; // validation failed
            }

            _results.Clear();
            _requestCount = 0;
            _matchCount   = 0;
            _vulnCount    = 0;
            _bypassCount  = 0;
            _cnt2xx = _cnt3xx = _cnt4xx = _cnt5xx = 0;
            TxtStatRequests.Text = "0";
            TxtStatMatches.Text  = "0";
            TxtStatVulns.Text    = "0";
            TxtStatRps.Text      = "0";
            TxtBadge2xx.Text = TxtBadge3xx.Text = TxtBadge4xx.Text = TxtBadge5xx.Text = "0";
            DetailPanel.Visibility = Visibility.Collapsed;

            SetRunningState(true);
            AppendTerminal("[WebFuzzer] Starting fuzzer...");
            AppendTerminal($"[WebFuzzer] Target: {TxtUrl.Text}");

            if (idorTempFile != null)
                AppendTerminal($"[IDOR] Mode: scanning IDs {TxtIdorFrom.Text} → {TxtIdorTo.Text}");
            else
                AppendTerminal($"[WebFuzzer] Wordlist: {TxtWordlist.Text}");

            _cts = new CancellationTokenSource();
            _stopwatch.Restart();
            _statsTimer!.Start();

            try
            {
                bool detectionEnabled = ChkSmartDetection.IsChecked == true;
                if (detectionEnabled)
                    await SetupBaselineAsync();

                var options = BuildOptions(idorTempFile);
                var detectorForEngine = (detectionEnabled && _detector.IsReady) ? _detector : null;
                var engine = new FuzzEngine(options, OnResult, OnProgress, OnTerminalLine, detectorForEngine);
                await engine.RunAsync(_cts.Token);
            }
            catch (OperationCanceledException)
            {
                AppendTerminal("[WebFuzzer] Fuzzing stopped by user.");
            }
            catch (Exception ex)
            {
                var fullMsg = ex.InnerException != null ? $"{ex.Message} \u2192 {ex.InnerException.Message}" : ex.Message;
                AppendTerminal($"[ERROR] {fullMsg}");
                try { System.IO.File.AppendAllText("crash.log", $"{DateTime.Now:s} [BtnRun]\n{ex}\n\n"); } catch { }
            }
            finally
            {
                _stopwatch.Stop();
                _statsTimer!.Stop();
                SetRunningState(false);
                UpdateStats(null, null);
                AppendTerminal($"[WebFuzzer] Done. {_matchCount} matches" +
                    (_bypassCount > 0 ? $", {_bypassCount} retained by detection" : "") +
                    $", {_vulnCount} vulns found in {_stopwatch.Elapsed:mm\\:ss\\.fff}");

                // Dọn file IDOR temp — với retry nếu file vẫn còn bị giữ
                if (idorTempFile != null)
                {
                    for (int _retry = 0; _retry < 3; _retry++)
                    {
                        try
                        {
                            if (File.Exists(idorTempFile)) File.Delete(idorTempFile);
                            break; // thành công
                        }
                        catch (IOException)
                        {
                            // File còn đang bị đọc — chờ và thử lại
                            if (_retry < 2) await Task.Delay(150);
                        }
                        catch { break; } // lỗi khác → bỏ qua
                    }
                }
            }
        }

        private async Task SetupBaselineAsync()
        {
            const string BaselinePayload = "aaaa1234xyz";
            AppendTerminal($"[Detection] Setting up baseline with payload '{BaselinePayload}'...");

            try
            {
                var options = BuildOptions(null);
                var baselineResults = new List<FuzzResult>();

                var handler = new System.Net.Http.HttpClientHandler
                {
                    AllowAutoRedirect = options.FollowRedirects,
                    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
                };
                if (!string.IsNullOrEmpty(options.Proxy))
                {
                    handler.Proxy = new System.Net.WebProxy(options.Proxy);
                    handler.UseProxy = true;
                }

                using var client = new System.Net.Http.HttpClient(handler);
                client.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);

                for (int i = 0; i < 3; i++)
                {
                    if (_cts!.Token.IsCancellationRequested) break;

                    var request   = RequestBuilder.Build(options, BaselinePayload);
                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                    try
                    {
                        var response     = await client.SendAsync(request, _cts.Token);
                        stopwatch.Stop();
                        var responseBody = await response.Content.ReadAsStringAsync(_cts.Token);

                        baselineResults.Add(new FuzzResult
                        {
                            Word          = BaselinePayload,
                            Payload       = BaselinePayload,
                            Url           = request.RequestUri!.ToString(),
                            StatusCode    = (int)response.StatusCode,
                            ContentLength = responseBody.Length,
                            WordCount     = responseBody.Split(new[] { ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length,
                            LineCount     = responseBody.Split('\n').Length,
                            DurationMs    = stopwatch.ElapsedMilliseconds,
                            ResponseBody  = responseBody,
                            ContentType   = response.Content.Headers.ContentType?.ToString(),
                            Timestamp     = DateTime.UtcNow
                        });
                    }
                    catch (Exception ex)
                    {
                        AppendTerminal($"[Detection Error] Baseline request failed: {ex.Message}");
                    }

                    await Task.Delay(100, _cts!.Token);
                }

                if (baselineResults.Count > 0)
                {
                    var valid2xx = baselineResults.Where(r => r.StatusCode >= 200 && r.StatusCode < 300).ToList();
                    if (valid2xx.Count > 0)
                    {
                        _detector.SetBaseline(valid2xx);
                        AppendTerminal($"[Detection] Baseline ready: " +
                            $"status={valid2xx[0].StatusCode}, " +
                            $"avgSize={valid2xx.Average(r => r.ContentLength):F0}, " +
                            $"avgTime={valid2xx.Average(r => r.DurationMs):F0}ms " +
                            $"(from {valid2xx.Count} 2xx samples)");
                    }
                    else
                    {
                        AppendTerminal("[Detection] ⚠ All baseline probes returned non-2xx — detection disabled.");
                    }
                }
            }
            catch (Exception ex)
            {
                AppendTerminal($"[Detection] ⚠ Baseline error: {ex.Message}");
            }
        }

        private void BtnStop_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            AppendTerminal("[WebFuzzer] Stop requested...");
        }

        private void BtnClear_Click(object sender, RoutedEventArgs e)
        {
            _results.Clear();
            _vulnCount = 0;
            _cnt2xx = _cnt3xx = _cnt4xx = _cnt5xx = 0;
            TxtStatRequests.Text = "0";
            TxtStatMatches.Text  = "0";
            TxtStatVulns.Text    = "0";
            TxtStatRps.Text      = "0";
            TxtBadge2xx.Text = TxtBadge3xx.Text = TxtBadge4xx.Text = TxtBadge5xx.Text = "0";
            DetailPanel.Visibility = Visibility.Collapsed;
            AppendTerminal("[WebFuzzer] Results cleared.");
        }

        // ── Callbacks từ FuzzEngine ──────────────────────────────────────────

        private void OnResult(FuzzResult result)
        {
            Dispatcher.Invoke(() =>
            {
                var vm = new FuzzResultViewModel(result);

                // ── Update status badges ─────────────────────────────────────
                if (result.StatusCode >= 200 && result.StatusCode < 300)
                { Interlocked.Increment(ref _cnt2xx); TxtBadge2xx.Text = _cnt2xx.ToString(); }
                else if (result.StatusCode >= 300 && result.StatusCode < 400)
                { Interlocked.Increment(ref _cnt3xx); TxtBadge3xx.Text = _cnt3xx.ToString(); }
                else if (result.StatusCode >= 400 && result.StatusCode < 500)
                { Interlocked.Increment(ref _cnt4xx); TxtBadge4xx.Text = _cnt4xx.ToString(); }
                else if (result.StatusCode >= 500)
                { Interlocked.Increment(ref _cnt5xx); TxtBadge5xx.Text = _cnt5xx.ToString(); }

                bool detectionEnabled = ChkSmartDetection.IsChecked == true;
                if (detectionEnabled && _detector.IsReady && !result.IsRetainedByDetection)
                {
                    var detection = _detector.Analyze(result, result.Word);
                    vm.Detection = detection;

                    if (detection.Severity >= Severity.Suspicious)
                    {
                        Interlocked.Increment(ref _vulnCount);
                        if (detection.Severity >= Severity.Likely)
                            AppendTerminal($"[VULN] {detection.Summary} | Payload: {result.Payload} | URL: {result.Url}");
                    }
                }
                else if (result.IsRetainedByDetection)
                {
                    if (_detector.IsReady)
                    {
                        var detection = _detector.Analyze(result, result.Word);
                        vm.Detection = detection;
                    }
                    
                    if (result.ConfirmationSummary != null && result.ConfirmationSummary.Contains("[VERIFIED]"))
                    {
                        AppendTerminal($"[✅ VERIFIED] {result.DetectedVulnType} | Payload: {result.Payload} | URL: {result.Url}");
                        Interlocked.Increment(ref _confirmedCount);
                    }

                    Interlocked.Increment(ref _vulnCount);
                    Interlocked.Increment(ref _bypassCount);
                }

                _results.Add(vm);
                Interlocked.Increment(ref _matchCount);
            });
        }

        private void OnProgress(long requestCount, string currentWord)
        {
            Interlocked.Exchange(ref _requestCount, requestCount);
        }

        private void OnTerminalLine(string line)
        {
            Dispatcher.Invoke(() => AppendTerminal(line));
        }

        // ── Stats Timer ──────────────────────────────────────────────────────
        private long _lastRequestCount;
        private DateTime _lastStatTime = DateTime.Now;

        private void UpdateStats(object? sender, EventArgs? e)
        {
            Dispatcher.Invoke(() =>
            {
                var now     = DateTime.Now;
                var elapsed = (now - _lastStatTime).TotalSeconds;
                var delta   = _requestCount - _lastRequestCount;
                var rps     = elapsed > 0 ? (int)(delta / elapsed) : 0;

                _lastRequestCount = _requestCount;
                _lastStatTime     = now;

                TxtStatRequests.Text = _requestCount.ToString();
                TxtStatMatches.Text  = _matchCount.ToString();
                TxtStatVulns.Text    = _vulnCount.ToString();
                TxtStatRps.Text      = rps.ToString();
                if (_bypassCount > 0)
                    TxtStatVulns.ToolTip = $"{_vulnCount} vuln signals, {_bypassCount} retained by detection";
            });
        }

        // ── Build FuzzOptions from UI ────────────────────────────────────────

        /// <summary>
        /// ✅ FIX: Nhận idorWordlistPath để override wordlist khi IDOR mode bật
        /// </summary>
        private FuzzOptions BuildOptions(string? idorWordlistPath = null)
        {
            static HashSet<int>? ParseIntSet(string? raw) =>
                string.IsNullOrWhiteSpace(raw) ? null :
                raw.Split(',', StringSplitOptions.RemoveEmptyEntries)
                   .Select(s => int.Parse(s.Trim()))
                   .ToHashSet();

            var method = (CmbMethod.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "GET";

            var wordlist = idorWordlistPath
                        ?? ResolveWordlistPath(TxtWordlist.Text.Trim());

            return new FuzzOptions
            {
                Url            = TxtUrl.Text.Trim(),
                Wordlist       = wordlist,
                Method         = method,
                MatchCodes     = string.IsNullOrWhiteSpace(TxtMatchCodes.Text)
                                 ? new[] { "200", "301", "302" }
                                 : TxtMatchCodes.Text.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToArray(),
                FilterCodes    = string.IsNullOrWhiteSpace(TxtFilterCodes.Text) ? null
                                 : TxtFilterCodes.Text.Split(','),
                FilterSize     = ParseIntSet(TxtFilterSize.Text),
                MatchRegex     = string.IsNullOrWhiteSpace(TxtMatchRegex.Text) ? null : TxtMatchRegex.Text,
                FilterRegex    = string.IsNullOrWhiteSpace(TxtFilterRegex.Text) ? null : TxtFilterRegex.Text,
                Threads        = int.TryParse(TxtThreads.Text, out var t) ? t : 40,
                TimeoutSeconds = int.TryParse(TxtTimeout.Text, out var to) ? to : 10,
                RateLimit      = int.TryParse(TxtRate.Text, out var r) ? r : 0,
                Proxy          = string.IsNullOrWhiteSpace(TxtProxy.Text) ? null : TxtProxy.Text,
                Headers        = string.IsNullOrWhiteSpace(TxtHeader.Text) ? null
                                 : TxtHeader.Text
                                     .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                                     .Select(h => h.Trim())
                                     .Where(h => h.Length > 0)
                                     .ToArray(),
                ContentType    = string.IsNullOrWhiteSpace(TxtContentType.Text) ? null : TxtContentType.Text.Trim(),
                Data           = string.IsNullOrWhiteSpace(TxtData.Text) ? null : TxtData.Text,
                AutoCalibrate   = ChkAutoCalibrate.IsChecked == true,
                EnableDetection = ChkSmartDetection.IsChecked == true,
                EnableConfirmation = ChkEnableConfirmation.IsChecked == true,
                Verbose         = ChkVerbose.IsChecked == true,
                FollowRedirects = ChkFollowRedirects.IsChecked == true,
                OutputFile      = string.IsNullOrWhiteSpace(TxtOutputFile.Text) ? null : TxtOutputFile.Text,
            };
        }

        private static string ResolveWordlistPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return path;
            if (Path.IsPathRooted(path)) return path;
            var resolved = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, path));
            return File.Exists(resolved) ? resolved : path;
        }

        // ── Validate ─────────────────────────────────────────────────────────
        private bool ValidateInputs()
        {
            var urlHasFuzz    = !string.IsNullOrWhiteSpace(TxtUrl.Text)    && TxtUrl.Text.Contains("FUZZ");
            var dataHasFuzz   = !string.IsNullOrWhiteSpace(TxtData.Text)   && TxtData.Text.Contains("FUZZ");
            var headerHasFuzz = !string.IsNullOrWhiteSpace(TxtHeader.Text) && TxtHeader.Text.Contains("FUZZ");
            bool idorMode     = ChkIdorMode.IsChecked == true;

            if (string.IsNullOrWhiteSpace(TxtUrl.Text))
            {
                System.Windows.MessageBox.Show("URL cannot be empty.",
                    "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            // ✅ FIX: IDOR mode không cần FUZZ trong URL — auto-detect sẽ xử lý
            if (!idorMode && !urlHasFuzz && !dataHasFuzz && !headerHasFuzz)
            {
                System.Windows.MessageBox.Show(
                    "FUZZ placeholder must appear in at least one of:\n\n" +
                    "  • URL:           https://example.com/FUZZ\n" +
                    "  • POST Data:     {\"password\":\"FUZZ\"}\n" +
                    "  • Custom Header: User-Agent: FUZZ\n\n" +
                    "Or enable IDOR Mode to auto-detect ID in URL.",
                    "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            // IDOR mode: skip wordlist check (sẽ dùng temp file)
            if (!idorMode)
            {
                var wordlistPath = ResolveWordlistPath(TxtWordlist.Text.Trim());
                if (string.IsNullOrWhiteSpace(wordlistPath) || !File.Exists(wordlistPath))
                {
                    System.Windows.MessageBox.Show(
                        $"Wordlist file not found:\n{wordlistPath}\n\nThư mục app: {AppContext.BaseDirectory}",
                        "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
            }
            return true;
        }

        // ── UI State ─────────────────────────────────────────────────────────
        private void SetRunningState(bool running)
        {
            BtnRun.IsEnabled  = !running;
            BtnStop.IsEnabled = running;

            StatusDot.Fill = running
                ? new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50))
                : new SolidColorBrush(Color.FromRgb(0x7D, 0x85, 0x90));

            TxtStatus.Text       = running ? "RUNNING" : "IDLE";
            TxtStatus.Foreground = running
                ? new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50))
                : new SolidColorBrush(Color.FromRgb(0x7D, 0x85, 0x90));
        }

        // ── Terminal ─────────────────────────────────────────────────────────
        private void AppendTerminal(string line)
        {
            TxtTerminal.Text += $"{DateTime.Now:HH:mm:ss.fff} {line}\n";
            TerminalScroll.ScrollToBottom();
        }

        private void ClearTerminal_Click(object sender, RoutedEventArgs e)
        {
            TxtTerminal.Text = "";
        }

        // ── File Dialogs ─────────────────────────────────────────────────────
        private void BrowseWordlist_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|JSON Files (*.json)|*.json|All Files (*.*)|*.*",
                Title  = "Select Wordlist / SQL Payload File"
            };
            if (dlg.ShowDialog() == true)
                TxtWordlist.Text = dlg.FileName;
        }

        private void BrowseOutput_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Filter   = "JSON (*.json)|*.json|CSV (*.csv)|*.csv",
                FileName = "results.json",
                Title    = "Save Results"
            };
            if (dlg.ShowDialog() == true)
                TxtOutputFile.Text = dlg.FileName;
        }

        // ── Export ───────────────────────────────────────────────────────────
        private void ExportJson_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog { Filter = "JSON (*.json)|*.json", FileName = "results.json" };
            if (dlg.ShowDialog() != true) return;

            var export = _results.Select(vm => new
            {
                vm.StatusCode,
                vm.Word,
                Payload = vm.Payload,       // ✅ Export payload SQL
                Url     = vm.Url,           // ✅ Export URL đầy đủ
                vm.ContentLength, vm.WordCount, vm.LineCount, vm.DurationMs,
                Detection = new
                {
                    Score    = vm.Detection.ConfidenceScore,
                    Severity = vm.Detection.Severity.ToString(),
                    VulnType = vm.Detection.PrimaryVulnType.ToString(),
                    vm.Detection.Summary,
                    Signals  = vm.Detection.Signals.Select(s => new
                    {
                        s.Name, s.Weight,
                        VulnType = s.VulnType.ToString(),
                        s.Evidence
                    })
                }
            });

            var json = JsonSerializer.Serialize(export, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(dlg.FileName, json);
            AppendTerminal($"[WebFuzzer] Exported {_results.Count} results to {dlg.FileName}");
        }

        private void ExportCsv_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = "results.csv" };
            if (dlg.ShowDialog() != true) return;

            // ✅ Thêm cột Payload và URL
            var sb = new StringBuilder("StatusCode,Payload,Url,Size,Words,Lines,DurationMs,Severity,VulnType,ConfidenceScore\n");
            foreach (var vm in _results)
            {
                sb.AppendLine($"{vm.StatusCode},{EscapeCsv(vm.Payload)},{EscapeCsv(vm.Url)}," +
                              $"{vm.ContentLength},{vm.WordCount},{vm.LineCount},{vm.DurationMs}," +
                              $"{vm.Detection.Severity},{vm.Detection.PrimaryVulnType},{vm.Detection.ConfidenceScore}");
            }

            File.WriteAllText(dlg.FileName, sb.ToString());
            AppendTerminal($"[WebFuzzer] Exported {_results.Count} results to {dlg.FileName}");
        }

        private static string EscapeCsv(string? value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Contains(',') || value.Contains('"') || value.Contains('\n')
                ? $"\"{value.Replace("\"", "\"\"")}\""
                : value;
        }

        private void CopyCommand_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(TxtCommandPreview.Text);
            AppendTerminal("[WebFuzzer] Command copied to clipboard.");
        }

        // ── Context Menu Handlers ────────────────────────────────────────────

        private void CopyPayload_Click(object sender, RoutedEventArgs e)
        {
            if (ResultsGrid.SelectedItem is FuzzResultViewModel vm)
            {
                Clipboard.SetText(vm.Payload);
                AppendTerminal($"[Copied] Payload: {vm.Payload}");
            }
        }

        private void CopyUrl_Click(object sender, RoutedEventArgs e)
        {
            if (ResultsGrid.SelectedItem is FuzzResultViewModel vm)
            {
                Clipboard.SetText(vm.Url);
                AppendTerminal($"[Copied] URL: {vm.Url}");
            }
        }

        private void OpenUrl_Click(object sender, RoutedEventArgs e)
        {
            if (ResultsGrid.SelectedItem is FuzzResultViewModel vm && !string.IsNullOrEmpty(vm.Url))
            {
                try
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = vm.Url,
                        UseShellExecute = true
                    });
                    AppendTerminal($"[Browser] Opening: {vm.Url}");
                }
                catch (Exception ex)
                {
                    AppendTerminal($"[ERROR] Cannot open URL: {ex.Message}");
                }
            }
        }
    }
}
