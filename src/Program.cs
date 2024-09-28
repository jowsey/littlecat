using CommandLine;
using littlecat.Utils;

namespace littlecat
{
    public class Options
    {
        [Option('c', "config", Required = false, HelpText = "Config file path", Default = "server.yaml")]
        public string Config { get; set; }
    }

    public static class Program
    {
        public static async Task Main(string[] args)
        {
            await Parser.Default.ParseArguments<Options>(args)
                .WithParsedAsync(async opts =>
                {
                    var server = new Server(ConfigHandler.ReadConfigAtPath(opts.Config));
                    await server.StartServer();
                });
        }
    }
}