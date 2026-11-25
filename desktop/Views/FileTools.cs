using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Templates;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    PageHost? fileToolsPage;

    void OpenFileTools()
    {
        if (fileToolsPage != null) { fileToolsPage.Activate(); return; }
        var page = fileToolsPage = NewPage("files", "檔案工具", 660, 540, keepAlive: true);
        var signatures = new FileAuditView(this, signatures: true);
        var hashes = new FileAuditView(this, signatures: false);
        var tabs = new TabControl { ItemsSource = new[] {
            new TabItem { Header = "資料夾連結", Content = FolderLinkPanel() },
            new TabItem { Header = "EXE 簽章", Content = signatures.View },
            new TabItem { Header = "SHA-256", Content = hashes.View }
        }};
        tabs.Resources["TabItemHeaderFontSize"] = Scale.Body;
        page.Content = tabs;
        page.Closed += (_, _) => { signatures.Dispose(); hashes.Dispose(); fileToolsPage = null; };
        page.Show(this);
    }

    Control FolderLinkPanel()
    {
        var source = new TextBox { Watermark = @"D:\tmp" };
        var link = new TextBox { Watermark = @"C:\tmp" };
        var status = new Notice();
        var allowed = OperatingSystem.IsWindows() && !preview;
        var fields = new StackPanel { Spacing = Scale.Regular };
        var create = Action("建立連結", async () => {
            var sourcePath = source.Text?.Trim() ?? "";
            var linkPath = link.Text?.Trim() ?? "";
            fields.IsEnabled = false;
            status.Show("Busy", "正在建立資料夾連結…");
            try {
                await Task.Run(() => FolderJunction.Create(sourcePath, linkPath));
                status.Show("Ok", "已建立連結。現在可透過 " + linkPath + " 存取 " + sourcePath + "。");
            } catch (Exception e) when (e is IOException or UnauthorizedAccessException or Win32Exception or ArgumentException or NotSupportedException) {
                var message = e is UnauthorizedAccessException or Win32Exception { NativeErrorCode: 5 or 1314 }
                    ? "Windows 拒絕建立連結。請確認可在該位置建立資料夾；系統位置可能需要管理員權限。"
                    : e.Message;
                status.Show("Error", message);
            } finally { fields.IsEnabled = true; }
        }, Icons.Plus, primary: true);
        void Refresh() => create.IsEnabled = allowed && !string.IsNullOrWhiteSpace(source.Text) && !string.IsNullOrWhiteSpace(link.Text);
        source.TextChanged += (_, _) => Refresh();
        link.TextChanged += (_, _) => Refresh();
        Refresh();

        async Task PickFolderAsync(bool pickSource)
        {
            try {
                var picked = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions {
                    Title = pickSource ? "選擇來源資料夾" : "選擇新連結的上層資料夾", AllowMultiple = false
                });
                if (picked.FirstOrDefault()?.TryGetLocalPath() is not { Length: > 0 } path) return;
                if (pickSource) source.Text = path;
                else {
                    var name = Path.GetFileName((source.Text ?? "").Trim().TrimEnd('\\', '/').Replace('/', Path.DirectorySeparatorChar));
                    link.Text = !string.IsNullOrEmpty(name) ? Path.Combine(path, name)
                        : Path.EndsInDirectorySeparator(path) ? path : path + Path.DirectorySeparatorChar;
                    link.Focus();
                    link.CaretIndex = link.Text.Length;
                }
            } catch (Exception e) { status.Show("Error", "無法選擇資料夾。" + e.Message); }
        }

        AutomationProperties.SetName(source, "來源資料夾");
        AutomationProperties.SetName(link, "新連結路徑");
        fields.Children.Add(Column(Scale.Snug, Label("來源資料夾"), Columns("*,Auto", source, Action("選擇資料夾…", async () => await PickFolderAsync(true)))));
        fields.Children.Add(Column(Scale.Snug, Label("新連結路徑"), Columns("*,Auto", link, Action("選擇上層…", async () => await PickFolderAsync(false)))));
        fields.Children.Add(Row(Scale.Small, create));
        var content = Column(Scale.Regular,
            Hint("在另一個位置開啟同一個資料夾。例如將 D:\\tmp 連結到 C:\\tmp，兩個路徑會讀寫同一批檔案。"),
            fields, Hint("新連結所在磁碟須使用 NTFS，上層資料夾須已存在。若新路徑已被占用，請改用其他名稱。"), status);
        content.Margin = new Thickness(0, Scale.Medium, 0, 0);
        return new ScrollViewer { Content = content, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
    }
}

internal sealed class FileAuditView : IDisposable
{
    internal Control View { get; }
    readonly Window owner;
    readonly bool signatures;
    readonly ObservableCollection<FileAuditEntry> results = new();
    readonly TextBox path = new(), expected = new() { Watermark = "預期 SHA-256（選填，單一檔案）", MaxLength = 128 };
    readonly CheckBox recursive = new() { Content = "包含子資料夾", IsChecked = true };
    readonly ListBox list = new() { SelectionMode = SelectionMode.Single };
    readonly TextBlock summary = Hint("");
    readonly SelectableTextBlock detail = new() { FontSize = Scale.Secondary, TextWrapping = TextWrapping.Wrap };
    readonly Notice notice = new();
    readonly Button start, cancel, save, copyHash;
    readonly StackPanel inputs;
    CancellationTokenSource? scan;
    bool disposed, exporting;
    int passed, attention;

    internal FileAuditView(Window owner, bool signatures)
    {
        this.owner = owner;
        this.signatures = signatures;
        path.Watermark = signatures ? "輸入資料夾完整路徑" : "輸入檔案或資料夾完整路徑";
        AutomationProperties.SetName(path, signatures ? "EXE 資料夾路徑" : "SHA-256 檔案或資料夾路徑");
        AutomationProperties.SetName(expected, "預期 SHA-256");
        var pickFolder = Action("選擇資料夾…", async () => await PickAsync(folder: true));
        var pathRow = signatures ? Columns("*,Auto", path, pickFolder)
            : Columns("*,Auto,Auto", path, Action("選擇檔案…", async () => await PickAsync(folder: false)), pickFolder);
        inputs = signatures ? Column(Scale.Small, pathRow, recursive) : Column(Scale.Small, pathRow, expected, recursive);
        start = Action(signatures ? "檢查簽章" : "計算 SHA-256", Start, primary: true);
        cancel = Action("取消掃描", () => { scan?.Cancel(); summary.Text = "正在取消…"; cancel!.IsEnabled = false; });
        save = Action("匯出 CSV…", Save);
        copyHash = Action("複製 SHA-256", CopyHash, Icons.Copy);
        copyHash.IsVisible = !signatures;
        var tools = Columns("*,Auto", Row(Scale.Snug, start, cancel), Row(Scale.Snug, copyHash, save));

        list.ItemsSource = results;
        list.ItemTemplate = new FuncDataTemplate<FileAuditEntry>((entry, _) => {
            if (entry == null) return new Border();
            var row = Columns("*,Auto", Label(entry.Path, Scale.Body), Label(entry.Status, Scale.Secondary, key: entry.Tone));
            row.ColumnSpacing = Scale.Regular;
            ToolTip.SetTip(row, entry.Path);
            return row;
        });
        list.SelectionChanged += (_, _) => {
            if (list.SelectedItem is FileAuditEntry entry) {
                detail.Text = string.Join('\n', new[] { entry.Path, entry.Hash, entry.Detail }.Where(value => value.Length > 0));
            } else detail.Text = "";
            detail.IsVisible = !string.IsNullOrEmpty(detail.Text);
            Refresh();
        };
        list.Res(TemplatedControl.BackgroundProperty, "Field");
        detail.Res(SelectableTextBlock.ForegroundProperty, "Muted");
        detail.IsVisible = false;

        var hint = signatures ? "批次驗證 Windows Authenticode 簽章，包含內嵌及系統目錄簽章。憑證撤銷狀態使用本機快取。"
            : "計算單一檔案或整個資料夾的 SHA-256。核對單一檔案時，可貼上來源提供的預期值。";
        var head = Column(Scale.Small, Hint(hint), inputs, tools, notice, summary);
        head.Margin = new Thickness(0, Scale.Medium, 0, Scale.Small);
        var selected = new ScrollViewer { MaxHeight = 90, Content = detail, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
        View = Rows("Auto,*,Auto", head, list, selected);
        path.TextChanged += (_, _) => Refresh();
        Refresh();
    }

    void Refresh()
    {
        var busy = scan != null;
        inputs.IsEnabled = !busy;
        start.IsEnabled = !busy && !exporting && !string.IsNullOrWhiteSpace(path.Text) && (!signatures || OperatingSystem.IsWindows());
        cancel.IsVisible = busy;
        cancel.IsEnabled = busy && !scan!.IsCancellationRequested;
        save.IsEnabled = !busy && !exporting && results.Count > 0;
        copyHash.IsEnabled = list.SelectedItem is FileAuditEntry { Hash.Length: > 0 };
    }

    async Task PickAsync(bool folder)
    {
        try {
            var picked = folder
                ? (await owner.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "選擇資料夾" })).FirstOrDefault()?.TryGetLocalPath()
                : (await owner.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "選擇檔案" })).FirstOrDefault()?.TryGetLocalPath();
            if (!disposed && !string.IsNullOrEmpty(picked)) {
                if (folder) expected.Text = "";
                path.Text = picked;
            }
        } catch (Exception e) { if (!disposed) notice.Show("Error", "無法開啟選擇器。" + e.Message); }
    }

    async void Start()
    {
        if (scan != null || disposed) return;
        var input = path.Text?.Trim() ?? "";
        var digest = signatures ? "" : expected.Text?.Trim() ?? "";
        var children = recursive.IsChecked == true;
        using var cts = new CancellationTokenSource();
        scan = cts;
        results.Clear();
        list.SelectedItem = null;
        passed = attention = 0;
        notice.Hide();
        summary.Text = "正在掃描…";
        Refresh();
        try {
            await Task.Run(() => FileAudit.ScanAsync(input, signatures, children, digest, ReportAsync, cts.Token));
            if (!disposed) Summarize(cts.IsCancellationRequested ? "已取消" : results.Count == 0 ? "未找到符合的檔案" : "掃描完成");
        } catch (OperationCanceledException) when (cts.IsCancellationRequested) {
            if (!disposed) Summarize("已取消");
        } catch (Exception e) {
            if (!disposed) { Summarize("掃描未完成"); notice.Show("Error", e.Message); }
        } finally {
            scan = null;
            if (!disposed) Refresh();
        }
    }

    async Task ReportAsync(IReadOnlyList<FileAuditEntry> batch) => await Dispatcher.UIThread.InvokeAsync(() => {
        if (disposed) return;
        foreach (var entry in batch) {
            results.Add(entry);
            if (entry.Tone == "Ok") passed++; else attention++;
        }
        if (scan?.IsCancellationRequested == false) Summarize("正在掃描");
    }, DispatcherPriority.Background);

    void Summarize(string phase) => summary.Text = $"{phase} · {(signatures ? "有效" : "完成")} {passed:N0} 項 · 待查看 {attention:N0} 項";

    async void CopyHash()
    {
        if (list.SelectedItem is not FileAuditEntry { Hash.Length: > 0 } entry || owner.Clipboard is not { } clipboard) return;
        try { await clipboard.SetTextAsync(entry.Hash); if (!disposed) notice.Show("Ok", "已複製 SHA-256。"); }
        catch (Exception e) { if (!disposed) notice.Show("Error", "無法複製。" + e.Message); }
    }

    async void Save()
    {
        if (scan != null || exporting || disposed || results.Count == 0) return;
        exporting = true;
        Refresh();
        try {
            var output = await owner.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions {
                Title = "匯出檢查結果", SuggestedFileName = signatures ? "exe-signatures.csv" : "sha256.csv",
                DefaultExtension = "csv", FileTypeChoices = [new FilePickerFileType("CSV") { Patterns = ["*.csv"] }]
            });
            if (output == null || disposed) return;
            var snapshot = results.ToArray();
            await using var stream = await output.OpenWriteAsync();
            if (stream.CanSeek) stream.SetLength(0);
            await using (var writer = new StreamWriter(stream, new UTF8Encoding(true), leaveOpen: true)) {
                await writer.WriteLineAsync("路徑,狀態,SHA-256,詳細資料");
                foreach (var entry in snapshot)
                    await writer.WriteLineAsync(string.Join(',', Csv(entry.Path), Csv(entry.Status), Csv(entry.Hash), Csv(entry.Detail))).ConfigureAwait(false);
            }
            await Dispatcher.UIThread.InvokeAsync(() => { if (!disposed) notice.Show("Ok", "已匯出 " + snapshot.Length.ToString("N0") + " 項結果。"); });
        } catch (Exception e) {
            await Dispatcher.UIThread.InvokeAsync(() => { if (!disposed) notice.Show("Error", "無法匯出。" + e.Message); });
        } finally {
            await Dispatcher.UIThread.InvokeAsync(() => { exporting = false; if (!disposed) Refresh(); });
        }
    }

    static string Csv(string value)
    {
        var leading = value.TrimStart();
        if (leading.Length > 0 && "=+-@".Contains(leading[0])) value = "'" + value;
        return '"' + value.Replace("\"", "\"\"") + '"';
    }

    public void Dispose() { disposed = true; scan?.Cancel(); }
}
