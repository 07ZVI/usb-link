using System.Text.Json;
using Avalonia.Controls;
using Avalonia.VisualTree;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    void SeedOpenSSHPreview()
    {
        using var sample = JsonDocument.Parse("""
        {"status":{"installed":true,"state":"Running","start_mode":"Auto","accounts":[{"sid":"S-1-5-21-1-2-3-1001","name":"USBWorker"}],"sid":"S-1-5-21-1-2-3-1001","username":"USBWorker","shared":false,"path":"C:\\Users\\USBWorker\\.ssh\\authorized_keys","keys":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"ssh-ed25519","comment":"MacBook · 工作公鑰","fingerprint":"SHA256:l6w0Jq9EXAMPLE4fZKRSX4goA2r2KqU8rBYg0H0eZ5iU","restricted":true}]}}
        """);
        UpdateOpenSSH(sample.RootElement);
    }

    void RunOpenSSHSmoke()
    {
        OpenSecurity(OpenSSHTab); SeedOpenSSHPreview();
        if (!sshLoaded || sshAccounts.ItemCount != 1 || !sshState.Text!.Contains("執行中") || sshKeys.Children.Count != 2)
            throw new InvalidOperationException("OpenSSH account/service/key state did not render");
        sshInput.Text = "ssh-ed25519 example";
        SSHControls();
        if (!sshImport.IsEnabled) throw new InvalidOperationException("OpenSSH import editor is disabled");
        sshPendingID = new string('b', 32); sshPendingAction = "openssh-import"; sshBusy = true;
        using var stale = JsonDocument.Parse("""{"action":"openssh-import","request_id":"cccccccccccccccccccccccccccccccc","problem":"stale"}""");
        {
            UpdateOpenSSH(stale.RootElement);
            if (!sshBusy || sshInput.Text != "ssh-ed25519 example") throw new InvalidOperationException("stale SSH reply changed pending state");
            using var failure = JsonDocument.Parse("""{"action":"openssh-import","request_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","problem":"Example import failure"}""");
            UpdateOpenSSH(failure.RootElement);
            if (sshBusy || sshLoaded || !sshRefresh.IsEnabled || sshInput.Text != "ssh-ed25519 example") throw new InvalidOperationException("SSH failure lost input or enabled stale mutations");
        }
        SeedOpenSSHPreview();
        var remove = sshKeys.GetVisualDescendants().OfType<Button>().First();
        remove.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
        if (securityWindow!.OwnedWindows.Count != 1) throw new InvalidOperationException("SSH delete confirmation missing");
        securityWindow.OwnedWindows.Single().Close();
        securityWindow.Close();
        if (sshBusy || sshLoaded || sshPendingID != "" || sshInput.Text != "") throw new InvalidOperationException("SSH close did not clear editor/wait state");
        OpenSecurity(OpenSSHTab); SeedOpenSSHPreview(); securityWindow!.Close();
        Console.WriteLine("OPENSSH_UI_SMOKE_OK");
    }
}
