using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    void RunSecuritySmoke()
    {
        // Preview-only regression: closing and reopening must release logical
        // parents, and scoped editor windows must attach to the current owner.
        try {
            if (smbAccountName != null || smbPassword != null || smbNewPassword != null || smbAccountProblem != null || smbGuest != null)
                throw new InvalidOperationException("account controls constructed before opening");
            if (!ReferenceEquals(Icons.SharedGeometry(Icons.Shield), Icons.SharedGeometry(Icons.Shield)))
                throw new InvalidOperationException("repeated icon geometry parsed twice");
            for (var i = 0; i < 3; i++) {
                OpenSMBAccount();
                using var account = JsonDocument.Parse("""{"account":{"exists":true,"username":"USBLinkShare","local_name":"USBLinkShare"},"guest":false,"problem":""}""");
                UpdateSMBAccount(account.RootElement);
                if (smbAccountName!.Text != "USBLinkShare")
                    throw new InvalidOperationException("lazy account window state rendering");
                smbAccountWindow!.Close();
                if (smbAccountWindow != null) throw new InvalidOperationException("account close lifecycle");
            }
            RunSMBAccountSmoke();
            for (var i = 0; i < 3; i++) {
                SeedSecurityPreview();
                if (renderedSecurityTabs.Count != 0 || connectionRows.Children.Count != 1)
                    throw new InvalidOperationException("hidden security lists populated before selection");
                securityTabs!.SelectedIndex = 1; RenderSecurityTab();
                securityTabs.SelectedIndex = 2; RenderSecurityTab();
                securityTabs.SelectedIndex = 3; RenderSecurityTab();
                if (firewallRows.Children.Count != 2 || connectionRows.Children.Count != 1 || usbRows.Children.Count != 11) throw new InvalidOperationException("security event rendering");
                var connection = connectionRows.Children[0];
                securityTabs.SelectedIndex = 0; securityTabs.SelectedIndex = 2; RenderSecurityTab();
                if (!ReferenceEquals(connection, connectionRows.Children[0])) throw new InvalidOperationException("unchanged security tab rebuilt");
                securityBusy=true;securityPendingID=new string('c',32);securityPendingAction="security-refresh";
                using(var stale=JsonDocument.Parse("""{"request_id":"dddddddddddddddddddddddddddddddd","action":"security-refresh","problem":"stale"}"""))UpdateSecurity(stale.RootElement);
                if(!securityBusy)throw new InvalidOperationException("stale security reply settled pending request");
                using(var failure=JsonDocument.Parse("""{"request_id":"cccccccccccccccccccccccccccccccc","action":"security-refresh","problem":"Example read error"}"""))UpdateSecurity(failure.RootElement);
                if(securityBusy||!securityRefresh.IsEnabled||connectionRows.Children[0]!=connection||!securityProblem.IsVisible)throw new InvalidOperationException("security failure must retain observations and recover controls");
                FailSecurityRequest("Example timeout");
                if(securityBusy||!securityRefresh.IsEnabled||connectionRows.Children[0]!=connection)throw new InvalidOperationException("security timeout recovery");
                if(i==0){SeedSecurityPreview();securityTabs.SelectedIndex=3;RenderSecurityTab();
                    var groupLabels=usbRows.Children.OfType<Border>().Where(b=>b.Child is TextBlock).Select(b=>((TextBlock)b.Child!).Text).ToArray();
                    if(!groupLabels.SequenceEqual(new[]{"輸入裝置 · 2","儲存裝置 · 1","網路裝置 · 1","控制裝置 · 1","其他與未知裝置 · 1"}))throw new InvalidOperationException("USB grouping must put input first and unknown last");
                    var usbVisuals=Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(usbRows).ToArray();
                    if(usbVisuals.OfType<Expander>().Any())throw new InvalidOperationException("technical USB details must stay behind info icon");
                    var infoButtons=usbVisuals.OfType<Button>().Where(b=>b.Flyout is Flyout).ToArray();
                    if(infoButtons.Length!=6||infoButtons.Any(b=>((Flyout)b.Flyout!).Content is not StackPanel panel||!panel.Children.OfType<SelectableTextBlock>().Any()))throw new InvalidOperationException("USB info must be accessible and selectable");
                    var usbTexts=usbVisuals.OfType<TextBlock>().Select(t=>t.Text??"").ToArray();
                    if(!usbTexts.Contains("鍵盤")||!usbTexts.Contains("滑鼠")||!usbTexts.Any(t=>t.Contains("E: · 工作資料")&&t.Contains("420 GB"))||!usbTexts.Any(t=>t.Contains("F: · 備份")&&t.Contains("尚未提供")))throw new InvalidOperationException("USB product/volume labels or null capacity rendering");
                    var bars=usbVisuals.OfType<ProgressBar>().ToArray();
                    if(bars.Length!=1 || Math.Abs(bars[0].Value-100.0*579/999)>0.01 || !usbTexts.Any(t=>t.Contains("USB 3.2")))throw new InvalidOperationException("USB speed and occupied ratio rendering");
                    if(USBUsedPercent(100,0,true)!=100 || USBUsedPercent(100,100,true)!=0 || USBUsedPercent(0,0,true)!=null || USBUsedPercent(100,101,true)!=null || USBUsedPercent(100,0,false)!=null)throw new InvalidOperationException("storage full, empty, invalid and unknown capacity semantics");
                    SaveSecurityPreview(securityWindow!,"usb-link-security-0140.png",true);
                    var firstInfo=(Flyout)infoButtons[0].Flyout!;firstInfo.ShowAt(infoButtons[0]);securityWindow!.UpdateLayout();
                    if(!firstInfo.IsOpen)throw new InvalidOperationException("USB info flyout did not open");
                    var infoContent=(Control)firstInfo.Content!;infoContent.UpdateLayout();
                    if(infoContent.Bounds.Width>0&&infoContent.Bounds.Height>0){using var bitmap=new Avalonia.Media.Imaging.RenderTargetBitmap(new PixelSize((int)Math.Ceiling(infoContent.Bounds.Width),(int)Math.Ceiling(infoContent.Bounds.Height)));bitmap.Render(infoContent);bitmap.Save(System.IO.Path.Combine(System.IO.Path.GetTempPath(),"usb-link-device-info-0140.png"));}
                    firstInfo.Hide();
                    var usbScroll=usbVisuals.OfType<ScrollViewer>().FirstOrDefault()??Avalonia.VisualTree.VisualExtensions.GetVisualAncestors(usbRows).OfType<ScrollViewer>().First();
                    usbScroll.Offset=new Vector(0,250);securityWindow.UpdateLayout();SaveSecurityPreview(securityWindow,"usb-link-storage-0140.png",true);
                    usbScroll.Offset=new Vector(0,usbScroll.Extent.Height);securityWindow.UpdateLayout();SaveSecurityPreview(securityWindow,"usb-link-security-lower-0140.png",true);

                }
                securityWindow!.Close();
                if (securityWindow != null) throw new InvalidOperationException("security close lifecycle");
            }
            for(var i=0;i<3;i++){
                OpenShareFolders();
                using var folders=JsonDocument.Parse("""
                {"folders":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaa","name":"Documents","path":"C:\u005cUsers\u005cExample\u005cDocuments","url":"http://10.6.9.1:10690/share/aaaaaaaaaaaaaaaaaaaaaaaa/"},{"id":"bbbbbbbbbbbbbbbbbbbbbbbb","name":"Media","path":"D:\u005cMedia","url":"http://10.6.9.1:10690/share/bbbbbbbbbbbbbbbbbbbbbbbb/"}],"problem":""}
                """);
                UpdateShareFolders(folders.RootElement);
                if(shareFolderRows.Children.Count!=2)throw new InvalidOperationException("multi-folder rendering");
                if(i==0)SaveSecurityPreview(shareFoldersWindow!,"usb-link-shares-0.8.7.png");
                shareFoldersWindow!.Close();if(shareFoldersWindow!=null)throw new InvalidOperationException("share close lifecycle");
            }
            OpenSecurity();
            using(var signedApps=JsonDocument.Parse("""{"active_links":1,"grants":[{"path":"C:\u005cPrograms\u005cTrusted.exe","decision":"allow"},{"path":"C:\u005cPrograms\u005cChanged.exe","decision":"block"},{"path":"C:\u005cPrograms\u005cUnsigned.exe","decision":"allow"}],"problem":""}"""))UpdateGateway(signedApps.RootElement);
            securityWindow!.UpdateLayout();
            var signatureLabels=Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(gatewayRows).OfType<TextBlock>().Where(t=>t.Text?.StartsWith("數位簽章：")==true).ToArray();
            if(signatureLabels.Length!=3)throw new InvalidOperationException("all gateway EXEs need signature status");
            var signerFixtures=new[]{("Valid","Example publisher"),("HashMismatch","Claimed publisher"),("NotSigned","")};
            for(var i=0;i<3;i++)ShowSignature(signatureLabels[i],ExecutableSignature.Parse(JsonSerializer.Serialize(new{status=signerFixtures[i].Item1,publisher=signerFixtures[i].Item2})));
            if(signatureLabels[1].Foreground is not SolidColorBrush red||red.Color!=Color.Parse("#C42B1C")||!signatureLabels[0].Text!.Contains("Example publisher"))throw new InvalidOperationException("signer and red invalid warning must be visible");
            securityMode.Text="介面預覽 · 簽章範例，不代表實際程式驗證";
            SaveSecurityPreview(securityWindow,"usb-link-gateway-signatures-0138.png");
            securityWindow.Close();
            using(var gateway=JsonDocument.Parse("""{"active_links":1,"grants":[{"path":"C:\u005cPrograms\u005cExample.exe","decision":"allow"}],"problem":""}""")){UpdateGateway(gateway.RootElement);if(gatewayRows.Children.Count!=1)throw new InvalidOperationException("gateway grants");}
            using(var request=JsonDocument.Parse("""{"request":{"id":"aaaaaaaaaaaaaaaaaaaaaaaa","path":"C:\u005cPrograms\u005cExample.exe","direction":"outbound","protocol":"UDP","remote":"10.6.9.2:4000"}}""")){ShowGatewayRequest(request.RootElement);if(gatewayPrompt==null)throw new InvalidOperationException("gateway prompt missing");SaveSecurityPreview(gatewayPrompt,"usb-link-permission-0.8.7.png");gatewayPrompt.Close();if(gatewayPrompt!=null)throw new InvalidOperationException("gateway prompt close");}
            foreach(var sample in new[]{("Valid","Publisher","valid"),("NotSigned","","unsigned"),("HashMismatch","Claimed publisher","invalid"),("NotTrusted","Claimed publisher","untrusted"),("UnknownError","","unverified"),("Valid","","unverified"),("unexpected","Publisher","unverified")}){
                var signature=ExecutableSignature.Parse(JsonSerializer.Serialize(new{status=sample.Item1,publisher=sample.Item2}));
                if((signature.Status is "invalid" or "untrusted")&&signature.Tone!="Error")throw new InvalidOperationException("invalid signatures must warn in red");
                if(signature.Status!=sample.Item3)throw new InvalidOperationException("signature state mapping");
                if(signature.Status!="valid"&&signature.Display.Contains("已驗證簽署者"))throw new InvalidOperationException("untrusted signer labeled verified");
            }
            if(ExecutableSignature.Parse("invalid JSON").Status!="unverified")throw new InvalidOperationException("malformed signature result accepted");
            if(ExecutableSignature.Parse(JsonSerializer.Serialize(new{status="Valid",publisher=new string('x',257)})).Status!="unverified")throw new InvalidOperationException("oversized signer accepted");
            if(ExecutableSignature.Parse(JsonSerializer.Serialize(new{status="Valid",publisher="Example\n\u202E"})).Publisher!="Example")throw new InvalidOperationException("signer control characters retained");
            Console.WriteLine("SECURITY_UI_SMOKE_OK");
            (Application.Current?.ApplicationLifetime as Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)?.Shutdown(0);
        } catch (Exception e) {
            Console.Error.WriteLine("SECURITY_UI_SMOKE_FAILED: " + e.Message);
            (Application.Current?.ApplicationLifetime as Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)?.Shutdown(1);
        }
    }
    void SaveSecurityPreview(Window window,string name,bool usb=false){
        if(!Program.SecuritySmoke)return;
        if(usb){var tabs=Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(window).OfType<TabControl>().FirstOrDefault();if(tabs!=null)tabs.SelectedIndex=3;}
        window.UpdateLayout();
        using var bitmap=new Avalonia.Media.Imaging.RenderTargetBitmap(new PixelSize((int)window.Bounds.Width,(int)window.Bounds.Height),new Vector(96,96));
        bitmap.Render(window);bitmap.Save(System.IO.Path.Combine("/private/tmp",name));
    }
    void SeedSecurityPreview()
    {
        OpenSecurity();
        using var sample = JsonDocument.Parse("""
        {"mode":"介面預覽 · 範例資料，不代表實機防護狀態","problem":"","rules":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","application":{"path":"C:\\Program Files\\Example\\Browser.exe"},"action":"allow","direction":"outbound","protocol":"tcp","remote":"any","port":443,"state":"applied"},{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","application":{"path":"C:\\Programs\\Example.exe"},"action":"block","direction":"outbound","protocol":"any","remote":"any","port":0,"state":"error","error":"FIREWALL_RULE_NOT_EFFECTIVE"}],"connections":[{"pid":1234,"path":"C:\\Program Files\\Example\\Browser.exe","local":"10.6.9.1:52000","remote":"203.0.113.1:443"}],"usb_devices":[{"name":"未識別裝置（範例）","types":["unknown"],"vid":"1111","pid":"0001"},{"name":"Portable SSD（範例）","types":["storage"],"usb":{"specification":"USB 3.2","speed":"10 Gbps 或以上（SuperSpeedPlus）","port_protocols":"USB 3.x"},"vid":"1111","pid":"0002","storage":[{"model":"Portable SSD（範例）","bytes":1000000000000,"volumes":[{"name":"工作資料","mount":"E:","bytes":999000000000,"free_bytes":420000000000,"space_known":true},{"name":"備份","mount":"F:","space_known":false}]}]},{"name":"G610（範例）","display_kind":"keyboard","types":["composite","keyboard","hid"],"vid":"046D","pid":"C333","node_count":5,"merged_roots":2,"location":"PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(3)"},{"name":"G903（範例）","display_kind":"mouse","types":["composite","keyboard","mouse","hid"]},{"name":"ASUS Aura 燈光控制器（範例）","display_kind":"lighting","types":["hid"],"vid":"0B05","pid":"1939","description":"依 VID/PID 識別為 ASUS 主板燈光控制介面（HID）。"},{"name":"Mac · USB Link 連線介面（範例）","display_kind":"link","types":["composite","network"]}]}
        """);
        UpdateSecurity(sample.RootElement);
    }
    Window? securityWindow;
    StackPanel firewallRows = new() { Spacing = 10 }, connectionRows = new() { Spacing = 10 }, usbRows = new() { Spacing = 10 };
    TextBlock securityMode = Label("手動應用程式規則 · 不變更預設聯網方式", 12, key: "Muted");
    TextBlock securityProblem = new() { FontSize = 12, TextWrapping = TextWrapping.Wrap, IsVisible = false };
    TextBlock securityCount = Label("正在讀取 USB 授權…", 12, key: "Muted");
    Button? discardPendingButton;
    bool securityBusy;
    string securityPendingID="",securityPendingAction="";
    DispatcherTimer? securityTimer;
    Button securityRefresh=null!;
    TabControl? securityTabs;
    JsonElement securitySnapshot;
    readonly HashSet<int> renderedSecurityTabs = new();

    static string Text(JsonElement e, string key) => e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
    static IEnumerable<JsonElement> Entries(JsonElement e, string key) => e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().ToArray() : Array.Empty<JsonElement>();
    void SendSecurity(object request)
    {
        if (preview) { securityProblem.Text = "介面預覽，不會執行系統操作。"; securityProblem.IsVisible = true; return; }
        if (securityBusy) return;
        if(securityWindow==null)return;
        securityBusy = true;
        securityRefresh.IsEnabled=false;
        var body=JsonSerializer.SerializeToElement(request).EnumerateObject().ToDictionary(p=>p.Name,p=>(object?)p.Value.Clone());
        securityPendingID=Guid.NewGuid().ToString("N");securityPendingAction=((JsonElement)body["action"]!).GetString()??"";
        body["request_id"]=securityPendingID;
        securityTimer?.Stop();var id=securityPendingID;var timer=new DispatcherTimer{Interval=TimeSpan.FromSeconds(60)};securityTimer=timer;
        timer.Tick+=(_,_)=>{timer.Stop();if(securityPendingID==id)FailSecurityRequest("等待 Windows 安全資料回覆逾時。操作結果尚未確認，請重新整理核對。");};timer.Start();
        securityCount.Text = "正在讀取或更新安全設定…";
        DesktopClient.SendRaw(JsonSerializer.Serialize(body)); 
    }
    void OpenSecurity()
    {
        if (securityWindow != null) { securityWindow.Activate(); return; }
        securityBusy = false; securityPendingID=securityPendingAction=""; securitySnapshot = default; renderedSecurityTabs.Clear();
        // Closed window children retain logical parents. Recreate the controls
        // instead of attaching the same instances to a second window.
        firewallRows = new() { Spacing = 10 }; connectionRows = new() { Spacing = 10 }; usbRows = new() { Spacing = 10 };
        securityMode = Label("USB 網關 · 應用程式授權", 12, key: "Muted");
        securityProblem = new() { FontSize = 12, TextWrapping = TextWrapping.Wrap, IsVisible = false };
        securityCount = Label("正在讀取 USB 授權…", 12, key: "Muted");
        securityProblem.Res(TextBlock.ForegroundProperty, "Warn");
        discardPendingButton = Action("移除未完成規則", () => ConfirmSecurity("移除未完成規則", "將移除這項未完成操作所屬的 USB Link 規則。原有應用程式規則也可能一併移除。", () => SendSecurity(new { action = "firewall-discard-pending" }))) ;
        discardPendingButton.IsVisible = false;
        var tabs = new TabControl { ItemsSource = new[] {
            new TabItem { Header = "USB 網關", Content = GatewayPanel() },
            new TabItem { Header = "全機手動規則", Content = SecurityList("選擇程式設定允許或阻止。Windows 既有規則仍會共同生效，阻止規則優先。", firewallRows, Action("新增規則", PickFirewallProgram)) },
            new TabItem { Header = "目前連線", Content = SecurityList("顯示目前 TCP 連線；不包含 UDP 或已被阻止的嘗試，也不能據此判定出站方向。", connectionRows) },
            new TabItem { Header = "USB 裝置", Content = SecurityList("依實體裝置合併與分組，省略空接口及空集線器。使用前批准尚未啟用；不會停用現有鍵盤、滑鼠。", usbRows, Action("USB Link 連線授權", () => Send("settings"))) }
        }};
        securityTabs = tabs;
        tabs.SelectionChanged += (_, _) => {
            if (tabs.SelectedIndex > 0 && securitySnapshot.ValueKind == JsonValueKind.Undefined && !securityBusy)
                SendSecurity(new { action = "security-refresh" });
            RenderSecurityTab();
        };
        foreach (var rows in new[] { firewallRows, connectionRows, usbRows }) rows.Children.Add(Label("正在讀取安全資料…", 13, key: "Muted"));
        securityWindow = new Window { Title = "USB Link · 安全管理", Width = 900, Height = 660, MinWidth = 700, MinHeight = 500, FontFamily = new FontFamily(Palette.FontStack), WindowStartupLocation = WindowStartupLocation.CenterOwner };
        securityWindow.Res(BackgroundProperty, "Window");
        securityRefresh=Action("重新整理", () => { if (tabs.SelectedIndex == 0) GatewayRequest(new { action = "gateway-refresh" }); else SendSecurity(new { action = "security-refresh" }); });
        securityWindow.Content = new Border { Padding = new Thickness(24), Child = Rows("Auto,Auto,*,Auto",
            Column(8, Columns("*,Auto", Label("安全管理", 24, FontWeight.SemiBold), Row(8, Action("工作管理員", OpenTaskManager), securityRefresh)), securityMode, Gap(12)),
            Column(8, securityProblem, discardPendingButton, Gap(8)), tabs, new Border { Padding = new Thickness(0, 12, 0, 0), Child = securityCount }) };
        securityWindow.Closed += (_, _) => { securityTimer?.Stop();securityPendingID=securityPendingAction="";CloseGatewayPanel();securityWindow.Content = null; securityWindow = null; securityTabs = null; securitySnapshot = default; renderedSecurityTabs.Clear(); securityBusy = false; };
        securityWindow.Show(this);
        GatewayRequest(new {action="gateway-refresh"});
    }
    Control SecurityList(string hint, StackPanel items, Control? extra = null)
    {
        var help = new TextBlock { Text = hint, FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 12, 0, 12) }.Res(TextBlock.ForegroundProperty, "Muted");
        return Rows("Auto,Auto,*", help, new Border { Padding = new Thickness(0, 0, 0, extra == null ? 0 : 12), Child = extra }, new ScrollViewer { Content = items, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled });
    }
    void ConfirmSecurity(string title, string message, Action yes)
    {
        if (securityWindow == null || securityBusy) return;
        var dialog = new Window { Title = title, Width = 480, SizeToContent = SizeToContent.Height, CanResize = false, WindowStartupLocation = WindowStartupLocation.CenterOwner, FontFamily = new FontFamily(Palette.FontStack) };
        dialog.Res(BackgroundProperty, "Window");
        dialog.Content = new Border { Padding = new Thickness(24), Child = Column(18, Label(title, 20, FontWeight.SemiBold), new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap }, Row(10, Action("取消", () => dialog.Close()), Action("確認", () => { dialog.Close(); yes(); }, primary: true))) };
        _ = dialog.ShowDialog(securityWindow);
    }
    async void PickFirewallProgram()
    {
        if (securityWindow == null || securityBusy) return;
        var owner = securityWindow;
        try {
            var files = await owner.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "選擇應用程式", AllowMultiple = false, FileTypeFilter = new[] { new FilePickerFileType("Windows 應用程式") { Patterns = new[] { "*.exe" } } } });
            var path = files.FirstOrDefault()?.TryGetLocalPath();
            if (!string.IsNullOrEmpty(path) && securityWindow == owner) EditFirewall(path);
        } catch (Exception) { securityProblem.Text = "無法開啟程式選擇器。"; securityProblem.IsVisible = true; }
    }
    void EditFirewall(string path)
    {
        if (securityWindow == null || securityBusy) return;
        var direction = new ComboBox { ItemsSource = new[] { "出站連線", "入站連線" }, SelectedIndex = 0, HorizontalAlignment = HorizontalAlignment.Stretch };
        var protocol = new ComboBox { ItemsSource = new[] { "所有協定", "TCP", "UDP" }, SelectedIndex = 0, HorizontalAlignment = HorizontalAlignment.Stretch };
        var remote = new TextBox { Text = "any", Watermark = "any、IP 位址或網段" };
        var port = new TextBox { Watermark = "留空：所有連接埠", IsEnabled = false };
        protocol.SelectionChanged += (_, _) => { port.IsEnabled = protocol.SelectedIndex != 0; if (!port.IsEnabled) port.Text = ""; };
        var problem = new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12 }.Res(TextBlock.ForegroundProperty, "Warn");
        var dialog = new Window { Title = "新增應用程式規則", Width = 560, SizeToContent = SizeToContent.Height, CanResize = false, WindowStartupLocation = WindowStartupLocation.CenterOwner, FontFamily = new FontFamily(Palette.FontStack) };
        dialog.Res(BackgroundProperty, "Window");
        void Save(string decision) {
            ushort p = 0;
            if (!string.IsNullOrWhiteSpace(port.Text) && (!ushort.TryParse(port.Text, out p) || p == 0)) { problem.Text = "連接埠必須在 1–65535 之間。"; return; }
            var address = remote.Text?.Trim() ?? ""; if (address.Length == 0) address = "any";
            dialog.Close();
            SendSecurity(new { action = "firewall-upsert", path, decision, direction = direction.SelectedIndex == 0 ? "outbound" : "inbound", protocol = protocol.SelectedIndex == 0 ? "any" : protocol.SelectedIndex == 1 ? "tcp" : "udp", remote = address, port = p });
        }
        dialog.Content = new Border { Padding = new Thickness(24), Child = Column(12,
            Label("新增應用程式規則", 20, FontWeight.SemiBold), new TextBlock { Text = path, TextWrapping = TextWrapping.Wrap, FontSize = 12 },
            Label("方向"), direction, Label("協定"), protocol, Label("遠端位址"), remote, Label("連接埠（出站：遠端；入站：本機）"), port,
            new TextBlock { Text = "規則會立即寫入 Windows 防火牆。程式檔案將核對雜湊；這不是數位簽章驗證。", TextWrapping = TextWrapping.Wrap, FontSize = 12 }.Res(TextBlock.ForegroundProperty, "Muted"), problem,
            Row(10, Action("取消", () => dialog.Close()), Action("允許", () => Save("allow")), Action("阻止", () => Save("block"), primary: true))) };
        _ = dialog.ShowDialog(securityWindow);
    }
    void UpdateSecurity(JsonElement d)
    {
        if (securityWindow == null) return;
        var id=Text(d,"request_id");
        if(id!=""&&(id!=securityPendingID||Text(d,"action")!=securityPendingAction)||id==""&&!preview)return;
        securityTimer?.Stop();securityPendingID=securityPendingAction="";securityBusy=false;securityRefresh.IsEnabled=true;
        if(id!="")ShareRequest(new{action="ui-result-ack",id,decision="security"});
        if(!d.TryGetProperty("rules",out _)||!d.TryGetProperty("connections",out _)||!d.TryGetProperty("usb_devices",out _)){
            FailSecurityRequest(Text(d,"problem") is {Length:>0} error?error:"Windows 安全資料回覆不完整。");
            if(Program.SecurityWireSmoke)ContinueSecurityWireSmoke();return;
        }
        securitySnapshot = d.Clone(); renderedSecurityTabs.Clear();
        securityMode.Text = Text(d, "mode");
        securityProblem.Text = Text(d, "problem"); securityProblem.IsVisible = securityProblem.Text.Length != 0;
        var rules = Entries(d, "rules").ToArray();
        var connections = Entries(d, "connections").ToArray();
        var devices = Entries(d, "usb_devices").ToArray();
        if (discardPendingButton != null) discardPendingButton.IsVisible = rules.Any(e => Text(e, "state") == "pending");
        int Total(string key,int fallback)=>d.TryGetProperty(key,out var n)&&n.TryGetInt32(out var count)?count:fallback;
        securityCount.Text = $"規則 {rules.Length}/{Total("rules_total",rules.Length)} · TCP {connections.Length}/{Total("connections_total",connections.Length)} · USB 裝置 {devices.Length}/{Total("usb_devices_total",devices.Length)} · {DateTime.Now:HH:mm:ss}";
        if(d.TryGetProperty("truncated",out var limited)&&limited.ValueKind==JsonValueKind.True)securityCount.Text+=" · 顯示部分觀測資料";
        ToolTip.SetTip(securityCount,securityCount.Text);
        RenderSecurityTab();
        if(Program.SecurityWireSmoke)ContinueSecurityWireSmoke();
    }
    void FailSecurityRequest(string problem){
        securityTimer?.Stop();securityPendingID=securityPendingAction="";securityBusy=false;securityRefresh.IsEnabled=true;
        securityProblem.Text=problem;securityProblem.IsVisible=true;securityCount.Text="安全資料尚未確認 · 可重新整理核對";
        if(securitySnapshot.ValueKind!=JsonValueKind.Object)foreach(var rows in new[]{firewallRows,connectionRows,usbRows}){rows.Children.Clear();rows.Children.Add(SMBHint("未取得 Windows 安全資料，請重新整理。"));}
    }
    void RenderSecurityTab()
    {
        var selected = securityTabs?.SelectedIndex ?? 0;
        if (selected == 0 || securitySnapshot.ValueKind != JsonValueKind.Object || !renderedSecurityTabs.Add(selected)) return;
        var rules = Entries(securitySnapshot, "rules").ToArray();
        var connections = Entries(securitySnapshot, "connections").ToArray();
        var devices = Entries(securitySnapshot, "usb_devices").ToArray();
        if (selected == 1) firewallRows.Children.Clear();
        if (selected == 2) connectionRows.Children.Clear();
        if (selected == 3) usbRows.Children.Clear();
        if (selected == 1)
        foreach (var r in rules) {
            var app = r.GetProperty("application"); var path = Text(app, "path"); var id = Text(r, "id"); var decision = Text(r, "action");
            var direction = Text(r, "direction"); var protocol = Text(r, "protocol"); var remote = Text(r, "remote"); var port = r.GetProperty("port").GetUInt16();
            var state = Text(r, "state") == "applied" ? "已核對系統規則" : Text(r, "state") == "error" ? "系統核對未通過" : "操作未完成";
            void Set(string value) => ConfirmSecurity("變更規則", $"{path}\n\n將此規則改為{(value == "allow" ? "允許" : "阻止")}。", () => SendSecurity(new { action = "firewall-upsert", id, decision = value, direction, protocol, remote, port }));
            var title = Label($"{(decision == "allow" ? "允許" : "阻止")} · {System.IO.Path.GetFileName(path)}", 15, FontWeight.SemiBold);
            firewallRows.Children.Add(Card(Column(7, Columns("*,Auto", title, Label(state, 12, key: Text(r, "state") == "applied" ? "Ok" : "Warn")),
                Label(path, 12, key: "Muted"), Label($"{(direction == "outbound" ? "出站" : "入站")} · {protocol.ToUpperInvariant()} · {remote} · {(port == 0 ? "所有連接埠" : port.ToString())}", 12), Label(Text(r,"error"),12,key:"Warn"),
                Row(8, Action("允許", () => Set("allow")), Action("阻止", () => Set("block")), Action("移除", () => ConfirmSecurity("移除規則", path + "\n\n移除後，程式將依 Windows 其他規則與預設設定聯網。", () => SendSecurity(new { action = "firewall-delete", id }))))), new Thickness(14)));
        }
        if (selected == 2)
        foreach (var c in connections.Take(200)) {
            var path = Text(c, "path"); var name = path.Length == 0 ? "無法讀取程式路徑" : System.IO.Path.GetFileName(path);
            var pid = c.TryGetProperty("pid", out var p) ? p.ToString() : "?";
            var buttons = Row(8, Action("設定程式規則", () => EditFirewall(path))); buttons.IsEnabled = path.Length != 0;
            connectionRows.Children.Add(Card(Column(6, Label(name + " · PID " + pid, 15, FontWeight.SemiBold), Label(path, 12, key: "Muted"), Label(Text(c, "local") + " → " + Text(c, "remote"), 12), buttons), new Thickness(14)));
        }
        if (selected == 3) RenderUSBDevices(devices);
        if (selected == 1 && rules.Length == 0) firewallRows.Children.Add(Label(securitySnapshot.TryGetProperty("rules_unavailable",out var unavailable)&&unavailable.ValueKind==JsonValueKind.True?"未取得完整規則列表，請查看讀取錯誤。":"尚無應用程式規則。新增規則後，將由 Windows 防火牆執行。", 13, key: "Muted"));
        if (selected == 2 && connections.Length == 0) connectionRows.Children.Add(Label("目前未讀到 TCP 連線；請同時查看上方是否有讀取錯誤。", 13, key: "Muted"));
        if (selected == 3 && devices.Length == 0) usbRows.Children.Add(Label("目前未讀到 USB 裝置；請同時查看上方是否有讀取錯誤。", 13, key: "Muted"));

    }
    static string USBKind(string value) => value switch { "keyboard" => "鍵盤", "mouse" => "滑鼠", "hid" => "HID 輸入裝置", "network" => "網路介面", "storage" => "儲存裝置", "hub" => "集線器", "audio" => "音訊", "camera" => "攝影機", "imaging" => "影像裝置", "media" => "媒體裝置", "composite" => "複合裝置", _ => "類型未知" };
}
