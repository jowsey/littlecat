namespace littlecat;

public static class Program
{
    // The natural-language version of Minecraft we target
    public const string TargetVersion = "1.21.5";

    // The Minecraft protocol version we target
    public const int TargetProtocol = 770;

    public static async Task Main()
    {
        var server = new Server.Server();
        server.Start();
        await Task.Delay(-1);
        server.Stop();
    }
}