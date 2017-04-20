public string allowedCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
public DateTime unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
public int validityPeriodSeconds = 30;

protected void btnGeneratePin_Click(object sender, EventArgs e)
{
    Response.Write(GetCode(txtSecret.Text, GetInterval(DateTime.Now)));
    Response.Write("<br>");
    Response.Write("Current Time: " + DateTime.Now);
    Response.Write("<br>");
    Response.Write("Valid until: " + DateTime.Now.AddSeconds(30));
}

long GetInterval(DateTime dateTime)
{
    TimeSpan elapsedTime = dateTime.ToUniversalTime() - unixEpoch;
    return (long)elapsedTime.TotalSeconds / validityPeriodSeconds;
}
byte[] Base32Encode(string source)
{
    var bits = source.ToUpper().ToCharArray().Select(c => Convert.ToString(allowedCharacters.IndexOf(c), 2).PadLeft(5, '0')).Aggregate((a, b) => a + b);
    return Enumerable.Range(0, bits.Length / 8).Select(i => Convert.ToByte(bits.Substring(i * 8, 8), 2)).ToArray();
}
string GetCode(string secretKey, long timeIndex)
{
    var secretKeyBytes = Base32Encode(secretKey);
    HMACSHA1 hmac = new HMACSHA1(secretKeyBytes);
    byte[] challenge = BitConverter.GetBytes(timeIndex);
    if (BitConverter.IsLittleEndian) Array.Reverse(challenge);
    byte[] hash = hmac.ComputeHash(challenge);
    int offset = hash[19] & 0xf;
    int truncatedHash = hash[offset] & 0x7f;
    for (int i = 1; i < 4; i++)
    {
        truncatedHash <<= 8;
        truncatedHash |= hash[offset + i] & 0xff;
    }
    truncatedHash %= 1000000;
    return truncatedHash.ToString("D6");
}
