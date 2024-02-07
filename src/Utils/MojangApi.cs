using Newtonsoft.Json.Linq;

namespace littlecat.Utils;

public static class MojangApi
{
    private static readonly HttpClient Client = new();
    
    public static async Task<JObject> GetUserInfo(string username, string hash)
    {
        var url = $"https://sessionserver.mojang.com/session/minecraft/hasJoined?username={username}&serverId={hash}";
        
        var response = await Client.GetAsync(url);
        var responseString = await response.Content.ReadAsStringAsync();
        
        ThreadLogger.Log($"Retrieved user info for {username} with hash {hash}");

        return JObject.Parse(responseString);
    }
}