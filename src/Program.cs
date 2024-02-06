using littlecat.Utils;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace littlecat
{
    public static class Program
    {
        public static async Task Main(string[] args)
        {
            ThreadLogger.Log("Reading server.yaml");

            Config config;

            if (!File.Exists("server.yaml"))
            {
                var serializer = new SerializerBuilder()
                    .WithNamingConvention(CamelCaseNamingConvention.Instance)
                    .Build();

                config = new Config();
                var serializedConfig = serializer.Serialize(config);
                await File.WriteAllTextAsync("server.yaml", serializedConfig);
            }
            else
            {
                var configFile = await File.ReadAllTextAsync("server.yaml");

                var deserializer = new DeserializerBuilder()
                    .WithNamingConvention(CamelCaseNamingConvention.Instance)
                    .Build();

                config = deserializer.Deserialize<Config>(configFile);
            }


            var server = new Server(config);
            await server.StartServer();
        }
    }
}