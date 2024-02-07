using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using littlecat.Extensions;
using littlecat.Packets;
using littlecat.Utils;
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

namespace littlecat;

public class ClientState
{
    public required NetworkStream Stream;
    public CipherStream? CipherStream;

    // Handshake state
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

    public Server(Config configHandler)
    {
        _configHandler = configHandler;

        if (File.Exists(_configHandler.FaviconPath))
        {
            var faviconBytes = File.ReadAllBytes(_configHandler.FaviconPath);
            _faviconBase64 = Convert.ToBase64String(faviconBytes);
        }

        // god save me
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
        var keyPair = generator.GenerateKeyPair();
        
        _rsaDecrypt = CipherUtilities.GetCipher("RSA/None/PKCS1Padding");
        _rsaDecrypt.Init(false, keyPair.Private);

        _publicKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded();
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
            Packet packet;
            try
            {
                packet = ReadNextPacket(clientState);
            }
            catch (InvalidDataException e)
            {
                // bye bye :3
                ThreadLogger.Warn(e.ToString());
                client.Close();
                return;
            }

            ThreadLogger.Log($"Received packet: {packet.Id:G} ({packet.Id:X})");

            switch (packet)
            {
                case HandshakePacket handshakePacket:
                {
                    clientState.HandshakeNextState = handshakePacket.NextState;

                    ThreadLogger.Log("Handshake packet");

                    ThreadLogger.Log($"Protocol version: {handshakePacket.ProtocolVersion}");
                    ThreadLogger.Log($"Server address: {handshakePacket.ServerAddress}");
                    ThreadLogger.Log($"Server port: {handshakePacket.ServerPort}");
                    ThreadLogger.Log($"Next state: {handshakePacket.NextState:G}");
                    break;
                }
                case StatusRequestPacket:
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
                        ["favicon"] = _faviconBase64 != null ? "data:image/png;base64," + _faviconBase64 : null,
                        ["enforcesSecureChat"] = false,
                        ["previewsChat"] = false
                    };

                    SendPacket(
                        clientState,
                        new PacketBuilder(ClientboundPacketId.StatusResponse)
                            .AppendString(JsonConvert.SerializeObject(response))
                    );
                    break;
                }
                case PingRequestPacket pingRequestPacket:
                {
                    ThreadLogger.Log("Ping request packet");

                    SendPacket(
                        clientState,
                        new PacketBuilder(ClientboundPacketId.PongResponse)
                            .AppendLong(pingRequestPacket.Payload)
                    );

                    client.Close();
                    break;
                }
                case LoginStartPacket loginStartPacket:
                {
                    ThreadLogger.Log("Login start packet");
                    ThreadLogger.Log($"Player name: {loginStartPacket.PlayerName}");
                    ThreadLogger.Log($"Player UUID: {loginStartPacket.PlayerUuid}");

                    clientState.Username = loginStartPacket.PlayerName;

                    new Random().NextBytes(clientState.VerifyToken);
                    ThreadLogger.Log($"Generated verify token: {BitConverter.ToString(clientState.VerifyToken)}");

                    SendPacket(
                        clientState,
                        new PacketBuilder(ClientboundPacketId.EncryptionRequest)
                            .AppendString("") // server id
                            .AppendLengthPrefixedBytes(_publicKeyDer)
                            .AppendLengthPrefixedBytes(clientState.VerifyToken)
                    );

                    clientState.WaitingForEncryptionResponse = true;
                    break;
                }
                case EncryptionResponsePacket encryptionResponsePacket:
                {
                    ThreadLogger.Log("Encryption response packet");

                    var sharedSecret = encryptionResponsePacket.SharedSecret;
                    var verifyToken = encryptionResponsePacket.VerifyToken;

                    var decryptedVerifyToken = _rsaDecrypt.DoFinal(verifyToken);
                    ThreadLogger.Log($"Decrypted verify token: {BitConverter.ToString(decryptedVerifyToken)}");

                    var decryptedSharedSecret = _rsaDecrypt.DoFinal(sharedSecret);
                    ThreadLogger.Log($"Decrypted shared secret: {BitConverter.ToString(decryptedSharedSecret)}");

                    if (clientState.VerifyToken.SequenceEqual(decryptedVerifyToken))
                    {
                        ThreadLogger.Log("Verify tokens match");

                        // initial vector and key are both the shared secret
                        var key = new KeyParameter(decryptedSharedSecret);
                        var iv = new ParametersWithIV(key, decryptedSharedSecret);
                        
                        _aesEncrypt = new PaddedBufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 8));
                        _aesEncrypt.Init(true, iv);
                        
                        _aesDecrypt = new PaddedBufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 8));
                        _aesDecrypt.Init(false, iv);
                        
                        clientState.CipherStream = new CipherStream(clientState.Stream, _aesDecrypt, _aesEncrypt);
                        clientState.EncryptionActive = true;
                    }

                    // update sha1 with server id, shared secret, and public key


                    var digest = decryptedSharedSecret.Concat(_publicKeyDer).ToMinecraftShaHexDigest();
                    ThreadLogger.Log($"Digest: {digest}");

                    var hasJoinedInfo = await MojangApi.GetUserInfo(clientState.Username!, digest);

                    ThreadLogger.Log($"Has joined info: {hasJoinedInfo}");

                    SendPacket(
                        clientState,
                        new PacketBuilder(ClientboundPacketId.LoginSuccess)
                        // todo
                    );

                    clientState.WaitingForEncryptionResponse = false;
                    break;
                }
            }
        }
    }

    private Packet ReadNextPacket(ClientState clientState)
    {
        Console.WriteLine(); // space between packets
        
        ThreadLogger.Log(clientState.HandshakeNextState.ToString("G"));

        ThreadLogger.Log(clientState.EncryptionActive.ToString());
        Stream stream = clientState.EncryptionActive
            ? clientState.CipherStream!
            : clientState.Stream;

        var packetLength = stream.ReadVarInt();
        ThreadLogger.Log($"Packet length: {packetLength}");

        var packetId = stream.ReadVarInt();
        ThreadLogger.Log($"Received packet id: {packetId:X}");

        switch (packetId)
        {
            case 0x00:
            {
                // ReSharper disable once ConvertIfStatementToSwitchStatement
                if (clientState.HandshakeNextState == HandshakeNextState.Status) return new StatusRequestPacket();

                if (clientState.HandshakeNextState == HandshakeNextState.Login)
                {
                    var playerName = stream.ReadString();
                    var playerUuid = stream.ReadUuid();

                    return new LoginStartPacket(playerName, playerUuid);
                }

                var protocolVersion = stream.ReadVarInt();
                var serverAddress = stream.ReadString();
                var serverPort = stream.ReadShort();
                var nextState = (HandshakeNextState)stream.ReadVarInt();

                return new HandshakePacket(
                    protocolVersion,
                    serverAddress,
                    serverPort,
                    nextState
                );
            }
            case 0x01:
            {
                if (clientState.WaitingForEncryptionResponse) // EncryptionResponsePacket
                {
                    var sharedSecret = stream.ReadLengthPrefixedBytes();
                    var verifyToken = stream.ReadLengthPrefixedBytes();
                    return new EncryptionResponsePacket(sharedSecret, verifyToken);
                }

                var payload = stream.ReadLong();
                return new PingRequestPacket(payload);
            }
            default:
                throw new InvalidDataException($"Unknown packet id: {packetId} (0x{packetId:X})");
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