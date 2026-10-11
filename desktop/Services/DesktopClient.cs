using System.Text.Json;
namespace Suhang.Desktop;
// The renderer sends intent. Only the independently authenticated core owns
// device authorization and system changes.
internal static class DesktopClient
{
    static readonly object WriterLock = new();
    internal static void Send(object request) => SendRaw(JsonSerializer.Serialize(request));
    internal static void SendRaw(string request)
    {
        lock (WriterLock) { Console.Out.WriteLine(request); Console.Out.Flush(); }
    }
}
