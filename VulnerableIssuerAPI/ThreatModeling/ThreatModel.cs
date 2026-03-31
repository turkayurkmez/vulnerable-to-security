namespace VulnerableIssuerAPI.ThreatModeling
{
    public enum StrideCategory
    {
        Spoofing, //Kimlik sahteciliği: başka biri gibi davranarak sisteme erişmeye çalışmak.
        Tampering, //Veri veya kaynakları izinsiz olarak değiştirme veya tahrif etme.
        Repudiation, //İşlemi gerçekleştiren kişinin işlemi inkar etme yeteneği, yani yapılan işlemin kaydının olmaması veya yetersiz olması.
        InformationDisclosure, //Bilgi sızıntısı: Hassas bilgilerin yetkisiz kişiler tarafından erişilmesi veya ifşa edilmesi.
        DenialOfService, //Hizmet reddi: Sistemin normal işleyişini engellemek veya hizmeti tamamen durdurmak amacıyla yapılan saldırılar.
        ElevationOfPrivilege //Ayrıcalık yükseltme: Saldırganın, normalde sahip olmadığı yetkilere sahip olmak için sistemdeki güvenlik açıklarını kullanması.
    }

    public enum SecurityLevel
    {
        Critical, // Kritik: Sistem veya veriler üzerinde ciddi bir etkisi olan güvenlik açığı.
        High, // Yüksek: Sistem veya veriler üzerinde önemli bir etkisi olan güvenlik açığı.
        Medium, // Orta: Sistem veya veriler üzerinde orta derecede bir etkisi olan güvenlik açığı.
        Low // Düşük: Sistem veya veriler üzerinde sınırlı bir etkisi olan güvenlik açığı.

    }

    public record ThreatEntry(
        string Id, // Tehdit girişinin benzersiz tanımlayıcısı.
        StrideCategory Category,
        SecurityLevel Severity,
        string Description,
        double CvssScore,
        string MitigationId,
        string? ExploitabilityDetails,
            string? AffectedComponent
    );


    public enum MitigationStatus
    {
        Open, // Açık: Henüz uygulanmamış veya tamamlanmamış bir hafifletme durumu.
        Planned, // Planlanmış: Uygulanması planlanan ancak henüz başlatılmamış bir hafifletme durumu.
        Implemented, // Uygulanmış: Halihazırda uygulanmış ve etkili olan bir hafifletme durumu.
        Verified // Doğrulanmış: Uygulanan hafifletmenin etkili olduğunu doğrulamak için test edilmiş ve onaylanmış bir durum.

    }

    public record MitigationEntry(
        string Id,
        MitigationStatus Status,
        string Strategy

        );

    public record ThreatModel(
        string SystemName,
        string Version,
        DateTime CreatedAt,
        IReadOnlyList<ThreatEntry> Threats,
        IReadOnlyList<MitigationEntry> Mitigations
    )
    {
        public IEnumerable<ThreatEntry> GetThreatsByCategory(StrideCategory category) =>
            Threats.Where(t => t.Category == category);

        public IEnumerable<ThreatEntry> CriticalAndHighPlanned() =>
            Threats.Where(t => (t.Severity == SecurityLevel.Critical || t.Severity == SecurityLevel.High) &&
                               Mitigations.FirstOrDefault(m => m.Id == t.MitigationId)?.Status == MitigationStatus.Planned);

        public MitigationEntry? GetMitigation(ThreatEntry threat) => Mitigations.FirstOrDefault(m => m.Id == threat.MitigationId);

    }





}
