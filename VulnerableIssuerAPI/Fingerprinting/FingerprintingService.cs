namespace VulnerableIssuerAPI.Fingerprinting
{
    public enum DeviceTrust
    {
        Knwon,
        Suspicious,
        New
    }

    public record DeviceEvaluation(DeviceTrust Trust, string Reason);

    //Normalde EF Core ile bir entity olarak tanımlanabilir, ancak burada basit bir servis olarak bırakıyoruz.
    public class FingerprintingService(ILogger<FingerprintingService> logger)
    {
        private readonly Dictionary<int, HashSet<string>> knownDevices = new();

        public DeviceEvaluation Evaluate(int userId, DeviceFingerprinting deviceFingerprint, string ipAddress)
        {
            //jailbreak ve benzeri ipuçlarını kontrol et
            if (deviceFingerprint.IsMobileHint && isJailBrokenSignal(deviceFingerprint))
            {
                return new DeviceEvaluation(DeviceTrust.Suspicious, "Jailbreak hint detected");
            }

            //boş user-agent: araç (bot/script) işareti:
            if (string.IsNullOrWhiteSpace(deviceFingerprint.UserAgent))
            {
                return new DeviceEvaluation(DeviceTrust.Suspicious, "Empty user-agent");
            }

            if (!knownDevices.TryGetValue(userId,out var known))
            {
                known = [];
            }

            if (known.Contains(deviceFingerprint.Hash))
            {
                return new DeviceEvaluation(DeviceTrust.Knwon, "Tanınan cihaz");
            }

            //Yeni cihaz, kullanıcıya bildirim gönderilebilir veya ek doğrulama (MFA) isteyebiliriz.
            logger.LogInformation("Yeni cihaz tespit edildi: UserId={UserId}, DeviceHash={DeviceHash}, IP={IP}", userId, deviceFingerprint.Hash, ipAddress);

            return new DeviceEvaluation(DeviceTrust.New, "Yeni cihaz, doğrulama gerekir!");

        }

        private bool isJailBrokenSignal(DeviceFingerprinting deviceFingerprint)
        {
            throw new NotImplementedException();
        }
    }
}
