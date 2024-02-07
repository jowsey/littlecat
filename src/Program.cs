using littlecat.Utils;

namespace littlecat
{
    public static class Program
    {
        public static async Task Main(string[] args)
        {
            var config = await ConfigHandler.GetServerConfig("server.yaml");
            
            var server = new Server(config);
            await server.StartServer();
        }
    }
}