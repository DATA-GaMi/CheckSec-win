namespace CheckSec.NetFx
{
    internal sealed class SecurityFeatureStatus
    {
        public SecurityFeatureStatus(string state, string details)
        {
            State = state;
            Details = details;
        }

        public string State { get; private set; }

        public string Details { get; private set; }

        public static SecurityFeatureStatus Enabled(string details)
        {
            return new SecurityFeatureStatus("Enabled", details);
        }

        public static SecurityFeatureStatus Disabled(string details)
        {
            return new SecurityFeatureStatus("Disabled", details);
        }

        public static SecurityFeatureStatus NotApplicable(string details)
        {
            return new SecurityFeatureStatus("N/A", details);
        }

        public static SecurityFeatureStatus Unknown(string details)
        {
            return new SecurityFeatureStatus("Unknown", details);
        }
    }
}
