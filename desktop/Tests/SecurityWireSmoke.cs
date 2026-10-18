using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;

namespace Suhang.Desktop;
public sealed partial class Dashboard
{
    int securityWireStage;
    void StartSecurityWireSmoke(){OpenSecurity(ConnectionsTab);}
    void ContinueSecurityWireSmoke(){
        if(securityBusy||securityPendingID!="")throw new InvalidOperationException("security reply did not settle request");
        if(securityWireStage==0){
            if(connectionRows.Children.Count!=2||!securityCount.Text!.Contains("TCP 2/1024"))throw new InvalidOperationException("security observations did not render with totals");
            securityWireStage=1;SendSecurity(new{action="firewall-delete",id=new string('a',32)});return;
        }
        if(securityWireStage==1){
            if(!securityProblem.Text!.Contains("SECURITY_OPERATION_BUSY")||connectionRows.Children.Count!=2||!securityRefresh.IsEnabled)throw new InvalidOperationException("busy error did not recover while retaining observations");
            securityWireStage=2;SendSecurity(new{action="security-refresh"});return;
        }
        if(connectionRows.Children.Count!=2||securityProblem.IsVisible)throw new InvalidOperationException("security refresh did not recover after error");
        securityWindow!.Close();
        if(securityPendingID!=""||gatewayPendingID!=""||securityBusy)throw new InvalidOperationException("security close did not clean requests");
        Console.WriteLine("SECURITY_STDIN_STDOUT_WIRE_SMOKE_OK");
        (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(0);
    }
}
