using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CheckSec.NetFx
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length == 0 || HasHelpFlag(args))
            {
                PrintUsage();
                return args.Length == 0 ? 1 : 0;
            }

            var options = ParseArguments(args);
            if (options == null)
            {
                PrintUsage();
                return 1;
            }

            if (!File.Exists(options.TargetPath))
            {
                Console.Error.WriteLine("[!] 文件不存在: {0}", options.TargetPath);
                return 2;
            }

            try
            {
                var analyzer = new PeImageAnalyzer();
                var result = analyzer.Analyze(options.TargetPath);

                if (options.JsonOutput)
                {
                    Console.WriteLine(JsonReportWriter.Write(result));
                }
                else
                {
                    PrintResult(result);
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] 分析失败: {0}", ex.Message);
                return 3;
            }
        }

        private static CommandLineOptions ParseArguments(IReadOnlyList<string> args)
        {
            var jsonOutput = false;
            string targetPath = null;

            for (var i = 0; i < args.Count; i++)
            {
                var arg = args[i];
                if (string.Equals(arg, "--json", StringComparison.OrdinalIgnoreCase))
                {
                    jsonOutput = true;
                    continue;
                }

                if (string.IsNullOrWhiteSpace(targetPath))
                {
                    targetPath = NormalizeInputPath(arg);
                    continue;
                }

                return null;
            }

            if (string.IsNullOrWhiteSpace(targetPath))
            {
                return null;
            }

            return new CommandLineOptions
            {
                JsonOutput = jsonOutput,
                TargetPath = targetPath
            };
        }

        private static bool HasHelpFlag(IEnumerable<string> args)
        {
            return args.Any(arg =>
                string.Equals(arg, "-h", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(arg, "/?", StringComparison.OrdinalIgnoreCase));
        }

        private static string NormalizeInputPath(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return value;
            }

            value = value.Trim().Trim('"');
            return Path.GetFullPath(value);
        }

        private static void PrintUsage()
        {
            Console.WriteLine("checksec-win (.NET Framework)");
            Console.WriteLine("用法:");
            Console.WriteLine("  checksec-win.exe [--json] <target.exe|dll|sys>");
            Console.WriteLine();
            Console.WriteLine("示例:");
            Console.WriteLine("  checksec-win.exe C:\\Windows\\System32\\notepad.exe");
            Console.WriteLine("  checksec-win.exe C:\\Windows\\System32\\kernel32.dll");
            Console.WriteLine("  checksec-win.exe C:\\Windows\\System32\\drivers\\acpi.sys");
            Console.WriteLine("  checksec-win.exe --json C:\\Windows\\System32\\notepad.exe");
        }

        private static void PrintResult(PeSecurityReport report)
        {
            Console.WriteLine("Target      : {0}", report.FilePath);
            Console.WriteLine("Image Kind  : {0}", report.ImageKind);
            Console.WriteLine("Subsystem   : {0}", report.Subsystem);
            Console.WriteLine("File Type   : {0}", report.Is64Bit ? "PE32+" : "PE32");
            Console.WriteLine("Machine     : {0}", report.Machine);
            Console.WriteLine("Managed CLR : {0}", FormatBoolean(report.IsManaged));
            Console.WriteLine("DllChars    : 0x{0:X4}", report.DllCharacteristics);
            Console.WriteLine("LoadConfig  : {0}", report.LoadConfigSummary);
            Console.WriteLine("Signed      : {0}", report.Signature.Status);
            Console.WriteLine();

            Console.WriteLine("{0,-18} {1,-10} {2}", "Feature", "Status", "Details");
            Console.WriteLine(new string('-', 68));

            PrintFeature("ASLR", report.Aslr);
            PrintFeature("DEP / NX", report.Dep);
            PrintFeature("HighEntropyVA", report.HighEntropyVa);
            PrintFeature("CFG", report.ControlFlowGuard);
            PrintFeature("SafeSEH", report.SafeSeh);
            PrintFeature("ForceIntegrity", report.ForceIntegrity);
            PrintFeature("AppContainer", report.AppContainer);
            PrintFeature("GS Cookie", report.GsCookie);
            Console.WriteLine();

            Console.WriteLine("Signature");
            Console.WriteLine(new string('-', 68));
            Console.WriteLine("Status      : {0}", report.Signature.Status);
            Console.WriteLine("Subject     : {0}", NullToDash(report.Signature.Subject));
            Console.WriteLine("Issuer      : {0}", NullToDash(report.Signature.Issuer));
            Console.WriteLine("Thumbprint  : {0}", NullToDash(report.Signature.Thumbprint));
            Console.WriteLine("ValidTo     : {0}", NullToDash(report.Signature.ValidTo));
            Console.WriteLine("Chain       : {0}", NullToDash(report.Signature.ChainStatus));
            Console.WriteLine();

            Console.WriteLine("TLS");
            Console.WriteLine(new string('-', 68));
            Console.WriteLine("Directory   : {0}", report.Tls.HasDirectory ? "Present" : "Missing");
            Console.WriteLine("Dir Size    : 0x{0:X}", report.Tls.DirectorySize);
            Console.WriteLine("Callbacks   : {0}", report.Tls.HasCallbacks ? "Present" : "Missing");
            Console.WriteLine("Cb Count    : {0}", report.Tls.CallbackCount);
            Console.WriteLine("Cb Preview  : {0}", report.Tls.CallbackAddresses.Count == 0 ? "-" : string.Join(", ", report.Tls.CallbackAddresses));
            Console.WriteLine("Details     : {0}", NullToDash(report.Tls.Details));
            Console.WriteLine();

            Console.WriteLine("Sections");
            Console.WriteLine(new string('-', 68));
            Console.WriteLine("{0,-12} {1,10} {2,10} {3,10} {4}", "Name", "RawSize", "Entropy", "Flags", "Notes");
            foreach (var section in report.Sections)
            {
                Console.WriteLine(
                    "{0,-12} {1,10} {2,10:F2} {3,10} {4}",
                    section.Name,
                    section.SizeOfRawData,
                    section.Entropy,
                    section.ProtectionFlags,
                    string.IsNullOrEmpty(section.Notes) ? "-" : section.Notes);
            }

            Console.WriteLine();
            Console.WriteLine("Special Checks");
            Console.WriteLine(new string('-', 68));
            foreach (var check in report.SpecialChecks)
            {
                PrintFeature(check.Name, new SecurityFeatureStatus(check.Status, check.Details));
            }

            Console.WriteLine();
            Console.WriteLine("Red Flags");
            Console.WriteLine(new string('-', 68));
            if (report.RedFlags.Count == 0)
            {
                Console.WriteLine("None");
            }
            else
            {
                foreach (var flag in report.RedFlags)
                {
                    Console.WriteLine("- {0}", flag);
                }
            }
        }

        private static void PrintFeature(string name, SecurityFeatureStatus feature)
        {
            var previousColor = Console.ForegroundColor;
            Console.Write("{0,-18} ", name);

            Console.ForegroundColor = GetColor(feature.State);
            Console.Write("{0,-10}", feature.State);
            Console.ForegroundColor = previousColor;

            Console.WriteLine(" {0}", feature.Details);
        }

        private static ConsoleColor GetColor(string state)
        {
            switch (state)
            {
                case "Enabled":
                    return ConsoleColor.Green;
                case "Disabled":
                    return ConsoleColor.Red;
                default:
                    return ConsoleColor.Yellow;
            }
        }

        private static string FormatBoolean(bool value)
        {
            return value ? "Yes" : "No";
        }

        private static string NullToDash(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "-" : value;
        }
    }

    internal sealed class CommandLineOptions
    {
        public bool JsonOutput { get; set; }

        public string TargetPath { get; set; }
    }
}
