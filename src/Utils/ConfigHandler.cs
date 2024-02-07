using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace littlecat.Utils;

public struct Config
{
    public int MaxPlayers = 20;
    public string Motd = "A Minecraft Server";
    public int Port = 25565;
    public string FaviconPath = "server-icon.png";

    public Config()
    {
    }
}

public static class ConfigHandler
{
    public static async Task<Config> GetServerConfig(string path)
    {
        Config config;

        if (!File.Exists(path))
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
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .Build();

            var configFile = await File.ReadAllTextAsync("server.yaml");

            config = deserializer.Deserialize<Config>(configFile);
        }

        return config;
    }
}