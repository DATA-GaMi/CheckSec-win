using System.Collections.Generic;

namespace CheckSec.NetFx
{
    internal sealed class PeSecurityReport
    {
        public string FilePath { get; set; }

        public string ImageKind { get; set; }

        public string Subsystem { get; set; }

        public string Machine { get; set; }

        public bool Is64Bit { get; set; }

        public bool IsManaged { get; set; }

        public ushort DllCharacteristics { get; set; }

        public string LoadConfigSummary { get; set; }

        public SecurityFeatureStatus Aslr { get; set; }

        public SecurityFeatureStatus Dep { get; set; }

        public SecurityFeatureStatus HighEntropyVa { get; set; }

        public SecurityFeatureStatus ControlFlowGuard { get; set; }

        public SecurityFeatureStatus SafeSeh { get; set; }

        public SecurityFeatureStatus ForceIntegrity { get; set; }

        public SecurityFeatureStatus AppContainer { get; set; }

        public SecurityFeatureStatus GsCookie { get; set; }

        public SignatureReport Signature { get; set; }

        public TlsReport Tls { get; set; }

        public List<SectionReport> Sections { get; set; }

        public List<SpecialCheckReport> SpecialChecks { get; set; }

        public List<string> RedFlags { get; set; }
    }

    internal sealed class SignatureReport
    {
        public string Status { get; set; }

        public string Subject { get; set; }

        public string Issuer { get; set; }

        public string Thumbprint { get; set; }

        public string ValidTo { get; set; }

        public string ChainStatus { get; set; }
    }

    internal sealed class SectionReport
    {
        public string Name { get; set; }

        public uint VirtualAddress { get; set; }

        public uint VirtualSize { get; set; }

        public uint SizeOfRawData { get; set; }

        public double Entropy { get; set; }

        public string ProtectionFlags { get; set; }

        public bool IsExecutable { get; set; }

        public bool IsWritable { get; set; }

        public bool IsReadable { get; set; }

        public string Notes { get; set; }
    }

    internal sealed class TlsReport
    {
        public bool HasDirectory { get; set; }

        public uint DirectorySize { get; set; }

        public bool HasCallbacks { get; set; }

        public int CallbackCount { get; set; }

        public List<string> CallbackAddresses { get; set; }

        public string Details { get; set; }
    }

    internal sealed class SpecialCheckReport
    {
        public string Name { get; set; }

        public string Status { get; set; }

        public string Details { get; set; }
    }

}
