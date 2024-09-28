using System.Reflection;
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
    public static Config ReadConfigAtPath(string path)
    {
        Config config;
        var serverDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        path = Path.Combine(serverDir!, path);

        if (!File.Exists(path))
        {
            var serializer = new SerializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .Build();

            config = new Config();
            var serializedConfig = serializer.Serialize(config);
            File.WriteAllText(path, serializedConfig);
        }
        else
        {
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .Build();

            var configFile = File.ReadAllText(path);

            config = deserializer.Deserialize<Config>(configFile);
        }

        return config;
    }
}