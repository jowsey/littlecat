namespace littlecat;

public static class Program
{
    public static async Task Main()
    {
        var server = new Server.Server();
        server.Start();
        await Task.Delay(-1);
        server.Stop();
    }
}