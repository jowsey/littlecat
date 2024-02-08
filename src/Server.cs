using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using littlecat.Extensions;
using littlecat.Packets;
using littlecat.Utils;
using Microsoft.Extensions.FileProviders;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SharpNBT;

namespace littlecat;

public enum ConnectionState
{
    Handshake,
    Configuration,
    Play
}

public enum HandshakeNextState
{
    Status = 1,
    Login = 2
}

public class ClientState
{
    public required NetworkStream Stream;
    public CipherStream? CipherStream;

    // State
    public ConnectionState ConnectionState = ConnectionState.Handshake;
    public HandshakeNextState HandshakeNextState;
    public bool WaitingForEncryptionResponse;

    // Encryption
    public readonly byte[] VerifyToken = new byte[4];
    public bool EncryptionActive;

    // User
    public string? Username;
}

public class Server
{
    private const string Version = "1.20.4";
    private const int ProtocolVersion = 765;

    private readonly Config _configHandler;

    private readonly string? _faviconBase64;

    private readonly byte[] _publicKeyDer;

    private readonly IBufferedCipher _rsaDecrypt;

    private PaddedBufferedBlockCipher? _aesEncrypt;
    private PaddedBufferedBlockCipher? _aesDecrypt;

    private List<CompoundTag> _registries = [];

    public Server(Config configHandler)
    {
        _configHandler = configHandler;

        // load favicon
        if (File.Exists(_configHandler.FaviconPath))
        {
            var faviconBytes = File.ReadAllBytes(_configHandler.FaviconPath);
            _faviconBase64 = Convert.ToBase64String(faviconBytes);
        }

        // generate rsa keys
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
        var keyPair = generator.GenerateKeyPair();

        _rsaDecrypt = CipherUtilities.GetCipher("RSA/None/PKCS1Padding");
        _rsaDecrypt.Init(false, keyPair.Private);

        _publicKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded();

        // Generate registry
        var embeddedProvider = new EmbeddedFileProvider(Assembly.GetExecutingAssembly());
        var embeddedFileInfo = embeddedProvider.GetFileInfo("res/registry_data.json");
        using var reader = new StreamReader(embeddedFileInfo.CreateReadStream());
        var registryJson = JObject.Parse(reader.ReadToEnd());
        
        // create registry tags from json
        // temporarily disable Console.WriteLine to avoid spam
        var initialOut = Console.Out;
        Console.SetOut(TextWriter.Null);
        
        foreach (var (registryName, registryObj) in registryJson)
        {
            var tb = new TagBuilder(registryName);
            tb.AddString("type", registryName);

            using (tb.NewList(TagType.Compound, "value"))
            {
                foreach (var entryObj in registryObj!["value"]!)
                {
                    var name = entryObj["name"]!.ToString();
                    var id = entryObj["id"]!.ToObject<int>();
                    var el = entryObj["element"]!;

                    using (tb.NewCompound(null))
                    {
                        tb.AddString("name", name);
                        tb.AddInt("id", id);

                        using (tb.NewCompound("element"))
                        {
                            switch (registryName)
                            {
                                case "minecraft:trim_pattern":
                                {
                                    tb.AddString("asset_id", el["asset_id"]!.ToString());
                                    tb.AddByte("decal", el["decal"]!.ToObject<byte>());
                                    tb.AddString("template_item", el["template_item"]!.ToString());

                                    using (tb.NewCompound("description"))
                                    {
                                        tb.AddString("translate", el["description"]!["translate"]!.ToString());
                                    }

                                    break;
                                }
                                case "minecraft:trim_material":
                                {
                                    tb.AddString("ingredient", el["ingredient"]!.ToString());
                                    tb.AddString("asset_name", el["asset_name"]!.ToString());
                                    tb.AddFloat("item_model_index", el["item_model_index"]!.ToObject<float>());

                                    using (tb.NewCompound("description"))
                                    {
                                        var description = el["description"]!;
                                        tb.AddString("translate", description["translate"]!.ToString());
                                        tb.AddString("color", description["color"]!.ToString());
                                    }

                                    if (el["override_armor_materials"] != null)
                                    {
                                        using (tb.NewCompound("override_armor_materials"))
                                        {
                                            foreach (var (key, value) in (JObject)el["override_armor_materials"]!)
                                            {
                                                tb.AddString(key, value!.ToString());
                                            }
                                        }
                                    }

                                    break;
                                }
                                case "minecraft:chat_type":
                                {
                                    var children = new[] { "chat", "narration" };

                                    foreach (var child in children)
                                    {
                                        using (tb.NewCompound(child))
                                        {
                                            tb.AddString("translation_key", el[child]!["translation_key"]!.ToString());
                                            if (el[child]!["style"] != null)
                                            {
                                                // todo add rest of style options (not used in vanilla registry)
                                                // https://wiki.vg/Text_formatting#Styling_fields
                                                using (tb.NewCompound("style"))
                                                {
                                                    var style = el[child]!["style"]!;
                                                    tb.AddString("color", style["color"]!.ToString());
                                                    tb.AddBool("italic", style["italic"]!.ToObject<bool>());
                                                }
                                            }

                                            using (tb.NewList(TagType.String, "parameters"))
                                            {
                                                foreach (var parameter in el[child]!["parameters"]!)
                                                {
                                                    tb.AddString(parameter.ToString());
                                                }
                                            }
                                        }
                                    }

                                    break;
                                }
                                case "minecraft:dimension_type":
                                {
                                    tb.AddByte("has_skylight", el["has_skylight"]!.ToObject<byte>());
                                    tb.AddByte("has_ceiling", el["has_ceiling"]!.ToObject<byte>());
                                    tb.AddByte("ultrawarm", el["ultrawarm"]!.ToObject<byte>());
                                    tb.AddByte("natural", el["natural"]!.ToObject<byte>());
                                    tb.AddDouble("coordinate_scale", el["coordinate_scale"]!.ToObject<double>());
                                    tb.AddByte("bed_works", el["bed_works"]!.ToObject<byte>());
                                    tb.AddByte("respawn_anchor_works", el["respawn_anchor_works"]!.ToObject<byte>());
                                    tb.AddInt("min_y", el["min_y"]!.ToObject<int>());
                                    tb.AddInt("height", el["height"]!.ToObject<int>());
                                    tb.AddInt("logical_height", el["logical_height"]!.ToObject<int>());
                                    tb.AddString("infiniburn", el["infiniburn"]!.ToString());
                                    tb.AddString("effects", el["effects"]!.ToString());
                                    tb.AddFloat("ambient_light", el["ambient_light"]!.ToObject<float>());
                                    tb.AddByte("piglin_safe", el["piglin_safe"]!.ToObject<byte>());
                                    tb.AddByte("has_raids", el["has_raids"]!.ToObject<byte>());
                                    tb.AddInt("monster_spawn_block_light_limit",
                                        el["monster_spawn_block_light_limit"]!.ToObject<int>());

                                    if (el["fixed_time"] != null)
                                    {
                                        tb.AddLong("fixed_time", el["fixed_time"]!.ToObject<long>());
                                    }

                                    var msll = el["monster_spawn_light_level"];
                                    if (msll!.Type == JTokenType.Integer)
                                    {
                                        tb.AddInt("monster_spawn_light_level", msll.ToObject<int>());
                                    }
                                    else
                                    {
                                        using (tb.NewCompound("monster_spawn_light_level"))
                                        {
                                            tb.AddString("type", msll["type"]!.ToString());
                                            using (tb.NewCompound("value"))
                                            {
                                                var value = msll["value"]!;
                                                tb.AddInt("min_inclusive", value["min_inclusive"]!.ToObject<int>());
                                                tb.AddInt("max_inclusive", value["max_inclusive"]!.ToObject<int>());
                                            }
                                        }
                                    }

                                    break;
                                }
                                case "minecraft:damage_type":
                                {
                                    tb.AddString("scaling", el["scaling"]!.ToString());
                                    tb.AddFloat("exhaustion", el["exhaustion"]!.ToObject<float>());
                                    tb.AddString("message_id", el["message_id"]!.ToString());

                                    if (el["death_message_type"] != null)
                                    {
                                        tb.AddString("death_message_type", el["death_message_type"]!.ToString());
                                    }

                                    if (el["effects"] != null)
                                    {
                                        tb.AddString("effects", el["effects"]!.ToString());
                                    }

                                    break;
                                }
                                case "minecraft:worldgen/biome":
                                {
                                    tb.AddByte("has_precipitation", el["has_precipitation"]!.ToObject<byte>());
                                    tb.AddFloat("temperature", el["temperature"]!.ToObject<float>());
                                    tb.AddFloat("downfall", el["downfall"]!.ToObject<float>());

                                    if (el["temperature_modifier"] != null)
                                    {
                                        tb.AddString("temperature_modifier", el["temperature_modifier"]!.ToString());
                                    }

                                    using (tb.NewCompound("effects"))
                                    {
                                        var effects = el["effects"]!;

                                        tb.AddInt("fog_color", effects["fog_color"]!.ToObject<int>());
                                        tb.AddInt("water_color", effects["water_color"]!.ToObject<int>());
                                        tb.AddInt("water_fog_color", effects["water_fog_color"]!.ToObject<int>());
                                        tb.AddInt("sky_color", effects["sky_color"]!.ToObject<int>());

                                        if (effects["foliage_color"] != null)
                                        {
                                            tb.AddInt("foliage_color", effects["foliage_color"]!.ToObject<int>());
                                        }

                                        if (effects["grass_color"] != null)
                                        {
                                            tb.AddInt("grass_color", effects["grass_color"]!.ToObject<int>());
                                        }

                                        if (effects["grass_color_modifier"] != null)
                                        {
                                            tb.AddString("grass_color_modifier",
                                                effects["grass_color_modifier"]!.ToString());
                                        }

                                        if (effects["particle"] != null)
                                        {
                                            using (tb.NewCompound("particle"))
                                            {
                                                var particle = effects["particle"]!;
                                                tb.AddFloat("probability", particle["probability"]!.ToObject<float>());

                                                using (tb.NewCompound("options"))
                                                {
                                                    var options = particle["options"]!;
                                                    tb.AddString("type", options["type"]!.ToString());
                                                    // todo add particle options data (not used in vanilla registry)
                                                    // https://wiki.vg/Registry_Data#Particle_options
                                                }
                                            }
                                        }

                                        var ambientSound = effects["ambient_sound"];
                                        if (ambientSound != null)
                                        {
                                            if (ambientSound.Type == JTokenType.String)
                                            {
                                                tb.AddString("ambient_sound", ambientSound.ToString());
                                            }
                                            else
                                            {
                                                using (tb.NewCompound("ambient_sound"))
                                                {
                                                    tb.AddString("sound_id", ambientSound["sound_id"]!.ToString());
                                                    tb.AddFloat("range", ambientSound["range"]!.ToObject<float>());
                                                }
                                            }
                                        }

                                        var moodSound = effects["mood_sound"];
                                        if (moodSound != null)
                                        {
                                            using (tb.NewCompound("mood_sound"))
                                            {
                                                tb.AddString("sound", moodSound["sound"]!.ToString());
                                                tb.AddInt("tick_delay", moodSound["tick_delay"]!.ToObject<int>());
                                                tb.AddInt("block_search_extent",
                                                    moodSound["block_search_extent"]!.ToObject<int>());
                                                tb.AddDouble("offset", moodSound["offset"]!.ToObject<double>());
                                            }
                                        }

                                        var additionsSound = effects["additions_sound"];
                                        if (additionsSound != null)
                                        {
                                            using (tb.NewCompound("additions_sound"))
                                            {
                                                tb.AddString("sound", additionsSound["sound"]!.ToString());
                                                tb.AddDouble("tick_chance",
                                                    additionsSound["tick_chance"]!.ToObject<double>());
                                            }
                                        }

                                        var music = effects["music"];
                                        if (music != null)
                                        {
                                            using (tb.NewCompound("music"))
                                            {
                                                tb.AddString("sound", music["sound"]!.ToString());
                                                tb.AddInt("min_delay", music["min_delay"]!.ToObject<int>());
                                                tb.AddInt("max_delay", music["max_delay"]!.ToObject<int>());
                                                tb.AddByte("replace_current_music",
                                                    music["replace_current_music"]!.ToObject<byte>());
                                            }
                                        }
                                    }

                                    break;
                                }
                            }
                        }
                    }
                }
            }

            var compound = tb.Create();
            _registries.Add(compound);
        }
        
        Console.SetOut(initialOut);
    }

    public async Task StartServer()
    {
        var ipEndPoint = new IPEndPoint(IPAddress.Any, _configHandler.Port);
        var listener = new TcpListener(ipEndPoint);

        try
        {
            listener.Start();

            while (true)
            {
                ThreadLogger.Log("Waiting for a connection...");

                var client = await listener.AcceptTcpClientAsync();

                ThreadPool.QueueUserWorkItem(HandleClient, client);
            }
        }
        catch (SocketException e)
        {
            ThreadLogger.Log($"SocketException: {e}");
        }
        finally
        {
            listener.Stop();
        }
    }

    private async void HandleClient(object? state)
    {
        if (state is not TcpClient client) return;

        ThreadLogger.Log($"Connected to {client.Client.RemoteEndPoint}");

        var clientState = new ClientState
        {
            Stream = client.GetStream()
        };

        while (client.Connected)
        {
            Stream stream = clientState.EncryptionActive
                ? clientState.CipherStream!
                : clientState.Stream;

            var packetLength = stream.ReadVarInt();
            var packetId = stream.ReadVarInt();

            ThreadLogger.Log($"Received packet with id {packetId:X} and length {packetLength}");

            if (clientState.ConnectionState == ConnectionState.Handshake)
            {
                switch (packetId)
                {
                    case 0x00:
                    {
                        // Status request
                        if (clientState.HandshakeNextState == HandshakeNextState.Status)
                        {
                            ThreadLogger.Log("Status request packet");

                            JObject response = new()
                            {
                                ["version"] = new JObject
                                {
                                    ["name"] = Version,
                                    ["protocol"] = ProtocolVersion
                                },
                                ["players"] = new JObject
                                {
                                    ["max"] = _configHandler.MaxPlayers,
                                    ["online"] = 0,
                                    // ["sample"] = new JArray
                                    // {
                                    //     new JObject
                                    //     {
                                    //         ["name"] = "Jowc",
                                    //         ["id"] = "1658caaf-0db9-43eb-ae89-1c22900d37c3"
                                    //     }
                                    // }
                                },
                                ["description"] = new JObject
                                {
                                    ["text"] = _configHandler.Motd
                                },
                                ["favicon"] = _faviconBase64 != null
                                    ? "data:image/png;base64," + _faviconBase64
                                    : null,
                                ["enforcesSecureChat"] = false,
                                ["previewsChat"] = false
                            };

                            SendPacket(clientState,
                                new PacketBuilder(ClientboundPacketId.StatusResponse)
                                    .AppendString(JsonConvert.SerializeObject(response))
                            );
                            break;
                        }

                        // Login start
                        if (clientState.HandshakeNextState == HandshakeNextState.Login)
                        {
                            ThreadLogger.Log("Login start packet");

                            var playerName = stream.ReadString();
                            var playerUuid = stream.ReadUuid();

                            ThreadLogger.Log($"Player name: {playerName}");
                            ThreadLogger.Log($"Player UUID: {playerUuid}");

                            clientState.Username = playerName;

                            new Random().NextBytes(clientState.VerifyToken);

                            SendPacket(clientState,
                                new PacketBuilder(ClientboundPacketId.EncryptionRequest)
                                    .AppendString("") // server id
                                    .AppendLengthPrefixedBytes(_publicKeyDer)
                                    .AppendLengthPrefixedBytes(clientState.VerifyToken)
                            );

                            clientState.WaitingForEncryptionResponse = true;
                            break;
                        }

                        _ = stream.ReadVarInt(); // protocol version
                        _ = stream.ReadString(); // server address
                        _ = stream.ReadShort(); // server port
                        var nextState = (HandshakeNextState)stream.ReadVarInt();

                        clientState.HandshakeNextState = nextState;

                        ThreadLogger.Log("Handshake packet");
                        break;
                    }
                    case 0x01:
                    {
                        // Encryption response
                        if (clientState.WaitingForEncryptionResponse)
                        {
                            ThreadLogger.Log("Encryption response packet");

                            var sharedSecret = stream.ReadLengthPrefixedBytes();
                            var verifyToken = stream.ReadLengthPrefixedBytes();

                            var decryptedVerifyToken = _rsaDecrypt.DoFinal(verifyToken);
                            var decryptedSharedSecret = _rsaDecrypt.DoFinal(sharedSecret);

                            if (!clientState.VerifyToken.SequenceEqual(decryptedVerifyToken))
                            {
                                ThreadLogger.Log("Verify tokens do not match");
                                client.Close();
                                break;
                            }

                            ThreadLogger.Log("Verify tokens match");

                            var key = new KeyParameter(decryptedSharedSecret);
                            var iv = new ParametersWithIV(key, decryptedSharedSecret);

                            _aesEncrypt = new PaddedBufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 8));
                            _aesEncrypt.Init(true, iv);

                            _aesDecrypt = new PaddedBufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 8));
                            _aesDecrypt.Init(false, iv);

                            clientState.CipherStream = new CipherStream(clientState.Stream, _aesDecrypt, _aesEncrypt);
                            clientState.EncryptionActive = true;

                            var digest = decryptedSharedSecret.Concat(_publicKeyDer).ToMinecraftShaHexDigest();

                            var hasJoinedInfo = await MojangApi.GetUserInfo(clientState.Username!, digest);
                            var uuid = hasJoinedInfo["id"]?.ToObject<string>();

                            var packetBuilder = new PacketBuilder(ClientboundPacketId.LoginSuccess)
                                .AppendUuid(UInt128.Parse(uuid!, NumberStyles.HexNumber))
                                .AppendString(clientState.Username!);

                            var numberOfProperties = hasJoinedInfo["properties"]?.Count() ?? 0;

                            packetBuilder.AppendVarInt(numberOfProperties);

                            if (numberOfProperties > 0)
                            {
                                foreach (var property in hasJoinedInfo["properties"]!)
                                {
                                    packetBuilder
                                        .AppendString(property["name"]!.ToObject<string>()!)
                                        .AppendString(property["value"]!.ToObject<string>()!);

                                    if (property["signature"] != null)
                                    {
                                        packetBuilder
                                            .AppendBoolean(true)
                                            .AppendString(property["signature"]!.ToObject<string>()!);
                                    }
                                }
                            }

                            SendPacket(clientState, packetBuilder);

                            clientState.WaitingForEncryptionResponse = false;
                            break;
                        }

                        // Ping request
                        ThreadLogger.Log("Ping request packet");
                        var payload = stream.ReadLong();

                        SendPacket(clientState,
                            new PacketBuilder(ClientboundPacketId.PongResponse)
                                .AppendLong(payload)
                        );

                        client.Close();
                        break;
                    }
                    case 0x03:
                    {
                        // Login acknowledged
                        ThreadLogger.Log("Login acknowledged packet");
                        clientState.ConnectionState = ConnectionState.Configuration;

                        SendPacket(clientState,
                            new PacketBuilder(ClientboundPacketId.PluginMessage)
                                .AppendString("minecraft:brand")
                                .AppendBytes("littlecat :3"u8.ToArray())
                        );

                        SendPacket(clientState,
                            new PacketBuilder(ClientboundPacketId.ChangeDifficulty)
                                .AppendByte(2)
                                .AppendBoolean(false)
                        );

                        foreach (var registry in _registries)
                        {
                            SendPacket(clientState,
                                new PacketBuilder(ClientboundPacketId.RegistryData)
                                    .AppendNbt(registry)
                            );
                        }

                        SendPacket(clientState, new PacketBuilder(ClientboundPacketId.FinishConfiguration));
                        break;
                    }
                    default:
                        throw new InvalidDataException($"Unknown packet id: {packetId} (0x{packetId:X})");
                }
            }
            else if (clientState.ConnectionState == ConnectionState.Configuration)
            {
                switch (packetId)
                {
                    case 0x01:
                    {
                        // Plugin message
                        ThreadLogger.Log("Plugin message packet");

                        var channel = stream.ReadString();
                        var data = stream.ReadExactly(packetLength - channel.Length);

                        ThreadLogger.Log($"Channel: {channel}");
                        ThreadLogger.Log($"Data: {BitConverter.ToString(data)}");

                        break;
                    }
                    case 0x02:
                    {
                        // Finish configuration
                        ThreadLogger.Log("Finish configuration packet");
                        clientState.ConnectionState = ConnectionState.Play;

                        SendPacket(clientState,
                            new PacketBuilder(ClientboundPacketId.Play)
                                .AppendInt(0) // player eid
                                .AppendBoolean(false) // is hardcore
                                .AppendVarInt(1) // dimension count
                                .AppendString("minecraft:overworld")
                                .AppendVarInt(0) // max players (ignored)
                                .AppendVarInt(8) // render distance
                                .AppendVarInt(8) // simulation distance
                                .AppendBoolean(false) // hide debug info
                                .AppendBoolean(true) // show respawn screen
                                .AppendBoolean(false) // limited crafting (ignored)
                                .AppendString("") // dimension type
                                .AppendString("minecraft:overworld") // name of joined dimension
                                .AppendLong(00000000) // first 8 bytes of world seed sha-256 hash
                                .AppendByte(0) // game mode
                                .AppendSByte(-1) // previous game mode
                                .AppendBoolean(false) // is debug mode
                                .AppendBoolean(false) // is flat
                                .AppendBoolean(false) // has death location
                                .AppendVarInt(0) // portal cooldown (might be ignored?)
                        );
                        
                        
                        break;
                    }
                }
            }

            Console.WriteLine();
        }
    }

    private void SendPacket(ClientState clientState, PacketBuilder packet)
    {
        var packetBytes = packet.GetBytes();

        if (clientState.EncryptionActive)
        {
            clientState.CipherStream!.Write(packetBytes, 0, packetBytes.Length);
            return;
        }

        clientState.Stream.Write(packetBytes, 0, packetBytes.Length);
    }
}