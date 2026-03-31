namespace VulnerableIssuerAPI.Models.StateMachine
{

    public enum TransactionStatus
    {

        Pending, //İslem beklemede
        PreAuthorized, //Ön onaylandı
        Authorized, //Onaylandı
        Clearing, //İslem bankalar arası temizleniyor (Gece yarısı batching)
        Settled, //İslem tamamlandı, fonlar transfer edildi
        Void, //İslem iptal edildi
        Declined, //İslem reddedildi
        Refunded, //İslem geri ödendi
    }


    public static class TransactionStateMap
    {
        public static readonly IReadOnlyDictionary<TransactionStatus, IReadOnlySet<TransactionStatus>>
            AllowedTransitions = new Dictionary<TransactionStatus, IReadOnlySet<TransactionStatus>>
            {
                [TransactionStatus.Pending] = new HashSet<TransactionStatus> {
                    TransactionStatus.PreAuthorized,
                    TransactionStatus.Declined
                },

                [TransactionStatus.PreAuthorized] = new HashSet<TransactionStatus>
                {
                     TransactionStatus.Authorized,
                     TransactionStatus.Void,
                     TransactionStatus.Declined
                },

                [TransactionStatus.Authorized] = new HashSet<TransactionStatus> { TransactionStatus.Clearing, TransactionStatus.Void },
                [TransactionStatus.Clearing] = new HashSet<TransactionStatus> { TransactionStatus.Settled, TransactionStatus.Declined },

                [TransactionStatus.Settled] = new HashSet<TransactionStatus> { TransactionStatus.Refunded },
                [TransactionStatus.Void] = new HashSet<TransactionStatus> (),
                [TransactionStatus.Declined] = new HashSet<TransactionStatus> (),
                [TransactionStatus.Refunded] = new HashSet<TransactionStatus> ()


            };

        public static bool IsAllowed(TransactionStatus from, TransactionStatus to)
        {
            return AllowedTransitions.TryGetValue(from, out var allowed) && allowed.Contains(to);
        }

          
    }
}

