namespace littlecat.Packets;

public class LoginStartPacket(string playerName, UInt128 playerUuid) : Packet(ServerboundPacketId.LoginStart)
{
    public readonly string PlayerName = playerName;
    public readonly UInt128 PlayerUuid = playerUuid;
}