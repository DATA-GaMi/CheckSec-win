using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace CheckSec.NetFx
{
    internal static class JsonReportWriter
    {
        public static string Write(PeSecurityReport report)
        {
            var builder = new StringBuilder();
            builder.AppendLine("{");
            AppendProperty(builder, "filePath", report.FilePath, 1, true);
            AppendProperty(builder, "imageKind", report.ImageKind, 1, true);
            AppendProperty(builder, "subsystem", report.Subsystem, 1, true);
            AppendProperty(builder, "machine", report.Machine, 1, true);
            AppendProperty(builder, "is64Bit", report.Is64Bit, 1, true);
            AppendProperty(builder, "isManaged", report.IsManaged, 1, true);
            AppendProperty(builder, "dllCharacteristics", string.Format("0x{0:X4}", report.DllCharacteristics), 1, true);
            AppendProperty(builder, "loadConfig", report.LoadConfigSummary, 1, true);
            AppendObjectStart(builder, "features", 1);
            AppendFeature(builder, "aslr", report.Aslr, 2, true);
            AppendFeature(builder, "dep", report.Dep, 2, true);
            AppendFeature(builder, "highEntropyVa", report.HighEntropyVa, 2, true);
            AppendFeature(builder, "cfg", report.ControlFlowGuard, 2, true);
            AppendFeature(builder, "safeSeh", report.SafeSeh, 2, true);
            AppendFeature(builder, "forceIntegrity", report.ForceIntegrity, 2, true);
            AppendFeature(builder, "appContainer", report.AppContainer, 2, true);
            AppendFeature(builder, "gsCookie", report.GsCookie, 2, false);
            AppendObjectEnd(builder, 1, true);

            AppendObjectStart(builder, "signature", 1);
            AppendProperty(builder, "status", report.Signature.Status, 2, true);
            AppendProperty(builder, "subject", report.Signature.Subject, 2, true);
            AppendProperty(builder, "issuer", report.Signature.Issuer, 2, true);
            AppendProperty(builder, "thumbprint", report.Signature.Thumbprint, 2, true);
            AppendProperty(builder, "validTo", report.Signature.ValidTo, 2, true);
            AppendProperty(builder, "chainStatus", report.Signature.ChainStatus, 2, false);
            AppendObjectEnd(builder, 1, true);

            AppendObjectStart(builder, "tls", 1);
            AppendProperty(builder, "hasDirectory", report.Tls.HasDirectory, 2, true);
            AppendProperty(builder, "directorySize", string.Format("0x{0:X}", report.Tls.DirectorySize), 2, true);
            AppendProperty(builder, "hasCallbacks", report.Tls.HasCallbacks, 2, true);
            AppendProperty(builder, "callbackCount", report.Tls.CallbackCount.ToString(CultureInfo.InvariantCulture), 2, true, true);
            AppendArrayStart(builder, "callbackPreview", 2);
            for (var i = 0; i < report.Tls.CallbackAddresses.Count; i++)
            {
                builder.Append("      ");
                AppendString(builder, report.Tls.CallbackAddresses[i]);
                builder.AppendLine(i == report.Tls.CallbackAddresses.Count - 1 ? string.Empty : ",");
            }
            AppendArrayEnd(builder, 2, true);
            AppendProperty(builder, "details", report.Tls.Details, 2, false);
            AppendObjectEnd(builder, 1, true);

            AppendArrayStart(builder, "sections", 1);
            for (var i = 0; i < report.Sections.Count; i++)
            {
                var section = report.Sections[i];
                builder.AppendLine("    {");
                AppendProperty(builder, "name", section.Name, 3, true);
                AppendProperty(builder, "virtualAddress", string.Format("0x{0:X8}", section.VirtualAddress), 3, true);
                AppendProperty(builder, "virtualSize", section.VirtualSize, 3, true);
                AppendProperty(builder, "rawSize", section.SizeOfRawData, 3, true);
                AppendProperty(builder, "entropy", section.Entropy.ToString("F2", CultureInfo.InvariantCulture), 3, true, true);
                AppendProperty(builder, "protection", section.ProtectionFlags, 3, true);
                AppendProperty(builder, "notes", section.Notes, 3, false);
                builder.Append("    }");
                builder.AppendLine(i == report.Sections.Count - 1 ? string.Empty : ",");
            }
            AppendArrayEnd(builder, 1, true);

            AppendArrayStart(builder, "specialChecks", 1);
            for (var i = 0; i < report.SpecialChecks.Count; i++)
            {
                var check = report.SpecialChecks[i];
                builder.AppendLine("    {");
                AppendProperty(builder, "name", check.Name, 3, true);
                AppendProperty(builder, "status", check.Status, 3, true);
                AppendProperty(builder, "details", check.Details, 3, false);
                builder.Append("    }");
                builder.AppendLine(i == report.SpecialChecks.Count - 1 ? string.Empty : ",");
            }
            AppendArrayEnd(builder, 1, true);

            AppendArrayStart(builder, "redFlags", 1);
            for (var i = 0; i < report.RedFlags.Count; i++)
            {
                builder.Append("    ");
                AppendString(builder, report.RedFlags[i]);
                builder.AppendLine(i == report.RedFlags.Count - 1 ? string.Empty : ",");
            }
            AppendArrayEnd(builder, 1, false);

            builder.Append('}');
            return builder.ToString();
        }

        private static void AppendFeature(StringBuilder builder, string name, SecurityFeatureStatus status, int indent, bool withComma)
        {
            AppendObjectStart(builder, name, indent);
            AppendProperty(builder, "state", status.State, indent + 1, true);
            AppendProperty(builder, "details", status.Details, indent + 1, false);
            AppendObjectEnd(builder, indent, withComma);
        }

        private static void AppendProperty(StringBuilder builder, string name, string value, int indent, bool withComma, bool rawValue)
        {
            Indent(builder, indent);
            AppendString(builder, name);
            builder.Append(": ");
            if (rawValue)
            {
                builder.Append(value);
            }
            else
            {
                AppendNullableString(builder, value);
            }

            builder.AppendLine(withComma ? "," : string.Empty);
        }

        private static void AppendProperty(StringBuilder builder, string name, string value, int indent, bool withComma)
        {
            AppendProperty(builder, name, value, indent, withComma, false);
        }

        private static void AppendProperty(StringBuilder builder, string name, bool value, int indent, bool withComma)
        {
            Indent(builder, indent);
            AppendString(builder, name);
            builder.Append(": ");
            builder.Append(value ? "true" : "false");
            builder.AppendLine(withComma ? "," : string.Empty);
        }

        private static void AppendProperty(StringBuilder builder, string name, uint value, int indent, bool withComma)
        {
            Indent(builder, indent);
            AppendString(builder, name);
            builder.Append(": ");
            builder.Append(value.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine(withComma ? "," : string.Empty);
        }

        private static void AppendObjectStart(StringBuilder builder, string name, int indent)
        {
            Indent(builder, indent);
            AppendString(builder, name);
            builder.AppendLine(": {");
        }

        private static void AppendObjectEnd(StringBuilder builder, int indent, bool withComma)
        {
            Indent(builder, indent);
            builder.Append('}');
            builder.AppendLine(withComma ? "," : string.Empty);
        }

        private static void AppendArrayStart(StringBuilder builder, string name, int indent)
        {
            Indent(builder, indent);
            AppendString(builder, name);
            builder.AppendLine(": [");
        }

        private static void AppendArrayEnd(StringBuilder builder, int indent, bool withComma)
        {
            Indent(builder, indent);
            builder.Append(']');
            builder.AppendLine(withComma ? "," : string.Empty);
        }

        private static void AppendNullableString(StringBuilder builder, string value)
        {
            if (value == null)
            {
                builder.Append("null");
                return;
            }

            AppendString(builder, value);
        }

        private static void AppendString(StringBuilder builder, string value)
        {
            builder.Append('"');
            if (!string.IsNullOrEmpty(value))
            {
                for (var i = 0; i < value.Length; i++)
                {
                    var c = value[i];
                    switch (c)
                    {
                        case '\\':
                        case '"':
                            builder.Append('\\').Append(c);
                            break;
                        case '\r':
                            builder.Append("\\r");
                            break;
                        case '\n':
                            builder.Append("\\n");
                            break;
                        case '\t':
                            builder.Append("\\t");
                            break;
                        default:
                            if (c < 32)
                            {
                                builder.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                            }
                            else
                            {
                                builder.Append(c);
                            }

                            break;
                    }
                }
            }

            builder.Append('"');
        }

        private static void Indent(StringBuilder builder, int level)
        {
            builder.Append(new string(' ', level * 2));
        }
    }
}
