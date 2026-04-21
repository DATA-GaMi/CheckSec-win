using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CheckSec.NetFx
{
    internal sealed class PeImageAnalyzer
    {
        private const ushort DosSignature = 0x5A4D;
        private const uint NtSignature = 0x00004550;
        private const ushort OptionalHeaderMagicPe32 = 0x10B;
        private const ushort OptionalHeaderMagicPe32Plus = 0x20B;

        private const ushort DllCharacteristicsDynamicBase = 0x0040;
        private const ushort DllCharacteristicsForceIntegrity = 0x0080;
        private const ushort DllCharacteristicsNxCompat = 0x0100;
        private const ushort DllCharacteristicsNoSeh = 0x0400;
        private const ushort DllCharacteristicsAppContainer = 0x1000;
        private const ushort DllCharacteristicsHighEntropyVa = 0x0020;
        private const ushort DllCharacteristicsGuardCf = 0x4000;

        private const int DirectoryEntryLoadConfig = 10;
        private const int DirectoryEntryBaseReloc = 5;
        private const int DirectoryEntryTls = 9;
        private const int DirectoryEntryComDescriptor = 14;
        private const int DirectoryEntryExport = 0;
        private const int DirectoryEntryDelayImport = 13;
        private const int DirectoryEntrySecurity = 4;
        private const int MaxSectionCount = 96;
        private const int MaxEntropySampleBytes = 64 * 1024;
        private const int MaxTlsCallbacksToInspect = 8;

        private const uint LoadConfigGuardCfInstrumented = 0x00000100;
        private const uint LoadConfigGuardCfFunctionTablePresent = 0x00000400;

        private const uint SectionContainsCode = 0x00000020;
        private const uint SectionMemoryExecute = 0x20000000;
        private const uint SectionMemoryRead = 0x40000000;
        private const uint SectionMemoryWrite = 0x80000000;
        private const ushort FileCharacteristicDll = 0x2000;

        public PeSecurityReport Analyze(string filePath)
        {
            using (var stream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var reader = new BinaryReader(stream, Encoding.UTF8, false))
            {
                var dosHeader = ReadDosHeader(reader);
                Ensure(dosHeader.LfaNew > 0 && dosHeader.LfaNew + 4 < stream.Length, "e_lfanew 超出文件范围。");

                stream.Position = dosHeader.LfaNew;
                Ensure(reader.ReadUInt32() == NtSignature, "无效的 NT Header 签名。");

                var fileHeader = ReadFileHeader(reader);
                var optionalHeaderStart = stream.Position;
                var optionalMagic = reader.ReadUInt16();
                var is64Bit = optionalMagic == OptionalHeaderMagicPe32Plus;
                Ensure(is64Bit || optionalMagic == OptionalHeaderMagicPe32, "不支持的 PE Optional Header。");
                Ensure(
                    optionalHeaderStart + fileHeader.SizeOfOptionalHeader <= stream.Length,
                    "Optional Header 超出文件范围。");

                stream.Position = optionalHeaderStart;
                var optionalHeader = ReadOptionalHeader(reader, is64Bit);
                var sections = ReadSections(reader, fileHeader.NumberOfSections);
                var sectionReports = BuildSectionReports(reader, sections);
                var loadConfig = TryReadLoadConfig(reader, optionalHeader, sections, is64Bit);
                var signature = AnalyzeSignature(filePath);
                var tls = TryReadTls(reader, optionalHeader, sections, is64Bit);
                var isManaged = optionalHeader.DataDirectories[DirectoryEntryComDescriptor].VirtualAddress != 0;
                var specialChecks = BuildSpecialChecks(
                    GetImageKind(filePath, fileHeader.Characteristics),
                    optionalHeader,
                    fileHeader,
                    sections,
                    tls);
                var safeSeh = BuildSafeSehStatus(is64Bit, optionalHeader, loadConfig);
                var cfg = BuildCfgStatus(optionalHeader, loadConfig);
                var gs = BuildGsStatus(loadConfig);
                var redFlags = BuildRedFlags(sectionReports, signature, cfg, gs, specialChecks);

                return new PeSecurityReport
                {
                    FilePath = filePath,
                    ImageKind = GetImageKind(filePath, fileHeader.Characteristics),
                    Subsystem = GetSubsystemName(optionalHeader.Subsystem),
                    Machine = GetMachineName(fileHeader.Machine),
                    Is64Bit = is64Bit,
                    IsManaged = isManaged,
                    DllCharacteristics = optionalHeader.DllCharacteristics,
                    LoadConfigSummary = loadConfig == null
                        ? "missing"
                        : string.Format("size=0x{0:X}, guard=0x{1:X8}, cookie=0x{2:X}", loadConfig.Size, loadConfig.GuardFlags, loadConfig.SecurityCookie),
                    Aslr = HasFlag(optionalHeader.DllCharacteristics, DllCharacteristicsDynamicBase)
                        ? SecurityFeatureStatus.Enabled("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE")
                        : SecurityFeatureStatus.Disabled("缺少 DYNAMIC_BASE"),
                    Dep = HasFlag(optionalHeader.DllCharacteristics, DllCharacteristicsNxCompat)
                        ? SecurityFeatureStatus.Enabled("IMAGE_DLLCHARACTERISTICS_NX_COMPAT")
                        : SecurityFeatureStatus.Disabled("缺少 NX_COMPAT"),
                    HighEntropyVa = is64Bit
                        ? (HasFlag(optionalHeader.DllCharacteristics, DllCharacteristicsHighEntropyVa)
                            ? SecurityFeatureStatus.Enabled("PE32+ 且启用 HIGH_ENTROPY_VA")
                            : SecurityFeatureStatus.Disabled("PE32+ 但缺少 HIGH_ENTROPY_VA"))
                        : SecurityFeatureStatus.NotApplicable("仅适用于 64 位映像"),
                    ControlFlowGuard = cfg,
                    SafeSeh = safeSeh,
                    ForceIntegrity = HasFlag(optionalHeader.DllCharacteristics, DllCharacteristicsForceIntegrity)
                        ? SecurityFeatureStatus.Enabled("启用 FORCE_INTEGRITY")
                        : SecurityFeatureStatus.Disabled("缺少 FORCE_INTEGRITY"),
                    AppContainer = HasFlag(optionalHeader.DllCharacteristics, DllCharacteristicsAppContainer)
                        ? SecurityFeatureStatus.Enabled("声明支持 AppContainer")
                        : SecurityFeatureStatus.Disabled("缺少 APPCONTAINER 标志"),
                    GsCookie = gs,
                    Signature = signature,
                    Tls = tls,
                    Sections = sectionReports,
                    SpecialChecks = specialChecks,
                    RedFlags = redFlags
                };
            }
        }

        private static DosHeader ReadDosHeader(BinaryReader reader)
        {
            var header = new DosHeader();
            header.Magic = reader.ReadUInt16();
            Ensure(header.Magic == DosSignature, "无效的 DOS Header 签名。");

            reader.BaseStream.Position = 0x3C;
            header.LfaNew = reader.ReadInt32();
            return header;
        }

        private static FileHeader ReadFileHeader(BinaryReader reader)
        {
            return new FileHeader
            {
                Machine = reader.ReadUInt16(),
                NumberOfSections = reader.ReadUInt16(),
                TimeDateStamp = reader.ReadUInt32(),
                PointerToSymbolTable = reader.ReadUInt32(),
                NumberOfSymbols = reader.ReadUInt32(),
                SizeOfOptionalHeader = reader.ReadUInt16(),
                Characteristics = reader.ReadUInt16()
            };
        }

        private static OptionalHeader ReadOptionalHeader(BinaryReader reader, bool is64Bit)
        {
            var header = new OptionalHeader();
            header.Magic = reader.ReadUInt16();
            reader.ReadByte();
            reader.ReadByte();
            reader.ReadUInt32();
            reader.ReadUInt32();
            reader.ReadUInt32();
            reader.ReadUInt32();
            reader.ReadUInt32();
            if (!is64Bit)
            {
                reader.ReadUInt32();
            }

            if (is64Bit)
            {
                reader.ReadUInt64();
            }
            else
            {
                reader.ReadUInt32();
            }

            reader.ReadUInt32();
            reader.ReadUInt32();
            reader.ReadUInt16();
            reader.ReadUInt16();
            reader.ReadUInt16();
            reader.ReadUInt16();
            reader.ReadUInt16();
            reader.ReadUInt16();
            reader.ReadUInt32();
            reader.ReadUInt32();
            reader.ReadUInt32();
            reader.ReadUInt32();
            header.Subsystem = reader.ReadUInt16();
            header.DllCharacteristics = reader.ReadUInt16();

            if (is64Bit)
            {
                header.ImageBase = reader.ReadUInt64();
                reader.ReadUInt64();
                reader.ReadUInt64();
                reader.ReadUInt64();
            }
            else
            {
                header.ImageBase = reader.ReadUInt32();
                reader.ReadUInt32();
                reader.ReadUInt32();
                reader.ReadUInt32();
            }

            reader.ReadUInt32();
            var numberOfRvaAndSizes = reader.ReadUInt32();

            header.DataDirectories = new DataDirectory[16];
            for (var i = 0; i < header.DataDirectories.Length; i++)
            {
                if (i < numberOfRvaAndSizes)
                {
                    header.DataDirectories[i] = new DataDirectory
                    {
                        VirtualAddress = reader.ReadUInt32(),
                        Size = reader.ReadUInt32()
                    };
                }
                else
                {
                    header.DataDirectories[i] = new DataDirectory();
                }
            }

            return header;
        }

        private static List<SectionHeader> ReadSections(BinaryReader reader, int count)
        {
            Ensure(count >= 0 && count <= MaxSectionCount, string.Format("Section 数量异常: {0}", count));
            var sections = new List<SectionHeader>(count);
            for (var i = 0; i < count; i++)
            {
                Ensure(reader.BaseStream.Position + 40 <= reader.BaseStream.Length, "Section Header 超出文件范围。");
                var nameBytes = reader.ReadBytes(8);
                var section = new SectionHeader
                {
                    Name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0'),
                    VirtualSize = reader.ReadUInt32(),
                    VirtualAddress = reader.ReadUInt32(),
                    SizeOfRawData = reader.ReadUInt32(),
                    PointerToRawData = reader.ReadUInt32()
                };

                reader.ReadUInt32();
                reader.ReadUInt32();
                reader.ReadUInt16();
                reader.ReadUInt16();
                section.Characteristics = reader.ReadUInt32();
                sections.Add(section);
            }

            return sections;
        }

        private static LoadConfigInfo TryReadLoadConfig(BinaryReader reader, OptionalHeader optionalHeader, IList<SectionHeader> sections, bool is64Bit)
        {
            var directory = optionalHeader.DataDirectories[DirectoryEntryLoadConfig];
            if (directory.VirtualAddress == 0 || directory.Size == 0)
            {
                return null;
            }

            var fileOffset = RvaToFileOffset(directory.VirtualAddress, sections);
            if (fileOffset < 0)
            {
                return null;
            }

            reader.BaseStream.Position = fileOffset;
            var loadConfig = new LoadConfigInfo();
            loadConfig.Size = reader.ReadUInt32();
            if (loadConfig.Size < (is64Bit ? 96u : 72u))
            {
                return null;
            }

            reader.BaseStream.Position = fileOffset + (is64Bit ? 88 : 60);
            loadConfig.SecurityCookie = is64Bit ? reader.ReadUInt64() : reader.ReadUInt32();
            loadConfig.SeHandlerTable = is64Bit ? reader.ReadUInt64() : reader.ReadUInt32();
            loadConfig.SeHandlerCount = is64Bit ? reader.ReadUInt64() : reader.ReadUInt32();

            var guardFlagsOffset = fileOffset + (is64Bit ? 144 : 88);
            if (loadConfig.Size >= (is64Bit ? 148u : 92u) && guardFlagsOffset + 4 <= reader.BaseStream.Length)
            {
                reader.BaseStream.Position = guardFlagsOffset;
                loadConfig.GuardFlags = reader.ReadUInt32();
            }

            return loadConfig;
        }

        private static TlsReport TryReadTls(BinaryReader reader, OptionalHeader optionalHeader, IList<SectionHeader> sections, bool is64Bit)
        {
            var directory = optionalHeader.DataDirectories[DirectoryEntryTls];
            var report = new TlsReport
            {
                HasDirectory = directory.VirtualAddress != 0 && directory.Size != 0,
                DirectorySize = directory.Size,
                HasCallbacks = false,
                CallbackCount = 0,
                CallbackAddresses = new List<string>(),
                Details = directory.VirtualAddress == 0 || directory.Size == 0 ? "未发现 TLS 目录。" : "TLS 目录已存在。"
            };

            if (!report.HasDirectory)
            {
                return report;
            }

            var tlsOffset = RvaToFileOffset(directory.VirtualAddress, sections);
            if (tlsOffset < 0)
            {
                report.Details = "TLS 目录 RVA 无法映射到文件偏移。";
                return report;
            }

            var minimumSize = is64Bit ? 40 : 24;
            if (tlsOffset + minimumSize > reader.BaseStream.Length)
            {
                report.Details = "TLS 目录超出文件范围。";
                return report;
            }

            reader.BaseStream.Position = tlsOffset;
            if (is64Bit)
            {
                reader.ReadUInt64();
                reader.ReadUInt64();
                reader.ReadUInt64();
                var addressOfCallbacks = reader.ReadUInt64();
                reader.ReadUInt32();
                reader.ReadUInt32();
                PopulateTlsCallbacks(reader, optionalHeader, sections, true, addressOfCallbacks, report);
            }
            else
            {
                reader.ReadUInt32();
                reader.ReadUInt32();
                reader.ReadUInt32();
                var addressOfCallbacks = reader.ReadUInt32();
                reader.ReadUInt32();
                reader.ReadUInt32();
                PopulateTlsCallbacks(reader, optionalHeader, sections, false, addressOfCallbacks, report);
            }

            return report;
        }

        private static void PopulateTlsCallbacks(
            BinaryReader reader,
            OptionalHeader optionalHeader,
            IList<SectionHeader> sections,
            bool is64Bit,
            ulong addressOfCallbacks,
            TlsReport report)
        {
            if (addressOfCallbacks == 0)
            {
                report.Details = "TLS 目录存在，但 AddressOfCallbacks 为 0。";
                return;
            }

            if (addressOfCallbacks < optionalHeader.ImageBase)
            {
                report.Details = "TLS 回调地址小于 ImageBase，已跳过。";
                return;
            }

            var callbacksRva = (uint)(addressOfCallbacks - optionalHeader.ImageBase);
            var callbacksOffset = RvaToFileOffset(callbacksRva, sections);
            if (callbacksOffset < 0)
            {
                report.Details = "TLS 回调数组无法映射到文件偏移。";
                return;
            }

            var pointerSize = is64Bit ? 8 : 4;
            for (var i = 0; i < MaxTlsCallbacksToInspect; i++)
            {
                var entryOffset = callbacksOffset + (i * pointerSize);
                if (entryOffset + pointerSize > reader.BaseStream.Length)
                {
                    break;
                }

                reader.BaseStream.Position = entryOffset;
                var callback = is64Bit ? reader.ReadUInt64() : reader.ReadUInt32();
                if (callback == 0)
                {
                    break;
                }

                report.HasCallbacks = true;
                report.CallbackCount++;
                report.CallbackAddresses.Add(string.Format(is64Bit ? "0x{0:X16}" : "0x{0:X8}", callback));
            }

            report.Details = report.HasCallbacks
                ? (report.CallbackCount == MaxTlsCallbacksToInspect
                    ? "TLS 回调已检测到，预览已截断到前 8 项。"
                    : "TLS 回调已检测到。")
                : "TLS 目录存在，但未发现非零回调项。";
        }

        private static List<SectionReport> BuildSectionReports(BinaryReader reader, IList<SectionHeader> sections)
        {
            var reports = new List<SectionReport>(sections.Count);
            foreach (var section in sections)
            {
                var rawBytes = ReadSectionBytes(reader, section);
                var entropy = CalculateEntropy(rawBytes);
                var isExecutable = (section.Characteristics & SectionMemoryExecute) == SectionMemoryExecute;
                var isReadable = (section.Characteristics & SectionMemoryRead) == SectionMemoryRead;
                var isWritable = (section.Characteristics & SectionMemoryWrite) == SectionMemoryWrite;
                var notes = BuildSectionNotes(section, entropy, isExecutable, isWritable);

                reports.Add(new SectionReport
                {
                    Name = string.IsNullOrWhiteSpace(section.Name) ? "<unnamed>" : section.Name,
                    VirtualAddress = section.VirtualAddress,
                    VirtualSize = section.VirtualSize,
                    SizeOfRawData = section.SizeOfRawData,
                    Entropy = entropy,
                    ProtectionFlags = string.Format(
                        "{0}{1}{2}",
                        isReadable ? "R" : "-",
                        isWritable ? "W" : "-",
                        isExecutable ? "X" : "-"),
                    IsExecutable = isExecutable,
                    IsWritable = isWritable,
                    IsReadable = isReadable,
                    Notes = notes
                });
            }

            return reports;
        }

        private static byte[] ReadSectionBytes(BinaryReader reader, SectionHeader section)
        {
            if (section.PointerToRawData == 0 || section.SizeOfRawData == 0)
            {
                return new byte[0];
            }

            if (section.PointerToRawData >= reader.BaseStream.Length)
            {
                return new byte[0];
            }

            reader.BaseStream.Position = section.PointerToRawData;
            var readableBytes = (int)Math.Min(section.SizeOfRawData, reader.BaseStream.Length - section.PointerToRawData);
            readableBytes = Math.Min(readableBytes, MaxEntropySampleBytes);
            return reader.ReadBytes(readableBytes);
        }

        private static string BuildSectionNotes(SectionHeader section, double entropy, bool isExecutable, bool isWritable)
        {
            var notes = new List<string>();
            if (isExecutable && isWritable)
            {
                notes.Add("RWX");
            }

            if (entropy >= 7.2d && section.SizeOfRawData >= 512)
            {
                notes.Add("HighEntropy");
            }

            if ((section.Characteristics & SectionContainsCode) == SectionContainsCode)
            {
                notes.Add("Code");
            }

            return string.Join(", ", notes);
        }

        private static List<SpecialCheckReport> BuildSpecialChecks(
            string imageKind,
            OptionalHeader optionalHeader,
            FileHeader fileHeader,
            IList<SectionHeader> sections,
            TlsReport tls)
        {
            var checks = new List<SpecialCheckReport>();
            var hasReloc = HasDirectory(optionalHeader, DirectoryEntryBaseReloc);
            var hasTls = HasDirectory(optionalHeader, DirectoryEntryTls);
            var hasDelayImport = HasDirectory(optionalHeader, DirectoryEntryDelayImport);
            var hasExport = HasDirectory(optionalHeader, DirectoryEntryExport);
            var hasSecurityDirectory = HasDirectory(optionalHeader, DirectoryEntrySecurity);

            checks.Add(CreateCheck(
                "Relocations",
                hasReloc,
                hasReloc ? "存在 Base Relocation 目录。" : "未发现 Base Relocation 目录。"));
            checks.Add(CreateCheck(
                "Security Dir",
                hasSecurityDirectory,
                hasSecurityDirectory ? "存在 Security 目录。" : "未发现 Security 目录。"));

            if (string.Equals(imageKind, "DLL", StringComparison.OrdinalIgnoreCase))
            {
                checks.Add(CreateCheck(
                    "Exports",
                    hasExport,
                    hasExport ? "存在导出目录。" : "未发现导出目录。"));
                checks.Add(CreateCheck(
                    "TLS Callbacks",
                    tls.HasCallbacks,
                    tls.Details));
                checks.Add(CreateCheck(
                    "Delay Imports",
                    hasDelayImport,
                    hasDelayImport ? "存在 Delay-Load Import 目录。" : "未发现 Delay-Load Import 目录。"));
            }
            else if (string.Equals(imageKind, "Driver", StringComparison.OrdinalIgnoreCase))
            {
                var isNativeSubsystem = optionalHeader.Subsystem == 1;
                var hasInitSection = HasSectionPrefix(sections, "INIT");
                var hasPageSection = HasSectionPrefix(sections, "PAGE");
                var isSystemFile = (fileHeader.Characteristics & 0x1000) == 0x1000;

                checks.Add(CreateCheck(
                    "Native Subsystem",
                    isNativeSubsystem,
                    isNativeSubsystem ? "驱动通常应使用 Native 子系统。" : "驱动文件未声明 Native 子系统。"));
                checks.Add(CreateCheck(
                    "INIT Section",
                    hasInitSection,
                    hasInitSection ? "存在 INIT 节区。" : "未发现 INIT 节区。"));
                checks.Add(CreateCheck(
                    "PAGE Section",
                    hasPageSection,
                    hasPageSection ? "存在 PAGE/PAGE* 节区。" : "未发现 PAGE/PAGE* 节区。"));
                checks.Add(CreateCheck(
                    "System Image",
                    isSystemFile,
                    isSystemFile ? "IMAGE_FILE_SYSTEM 已设置。" : "未设置 IMAGE_FILE_SYSTEM。"));
            }

            return checks;
        }

        private static SignatureReport AnalyzeSignature(string filePath)
        {
            try
            {
                var rawCertificate = X509Certificate.CreateFromSignedFile(filePath);
                if (rawCertificate == null)
                {
                    return new SignatureReport
                    {
                        Status = "Unsigned",
                        ChainStatus = "未检测到嵌入签名"
                    };
                }

                var certificate = new X509Certificate2(rawCertificate);
                var now = DateTime.Now;
                var status = certificate.NotBefore <= now && now <= certificate.NotAfter
                    ? "SignedPresent"
                    : "SignedExpired";

                return new SignatureReport
                {
                    Status = status,
                    Subject = certificate.Subject,
                    Issuer = certificate.Issuer,
                    Thumbprint = certificate.Thumbprint,
                    ValidTo = certificate.NotAfter.ToString("yyyy-MM-dd HH:mm:ss"),
                    ChainStatus = "未执行证书链联网校验"
                };
            }
            catch (CryptographicException)
            {
                return new SignatureReport
                {
                    Status = "Unsigned",
                    ChainStatus = "未检测到有效 Authenticode 签名"
                };
            }
            catch (Exception ex)
            {
                return new SignatureReport
                {
                    Status = "Unknown",
                    ChainStatus = ex.Message
                };
            }
        }

        private static SecurityFeatureStatus BuildSafeSehStatus(bool is64Bit, OptionalHeader optionalHeader, LoadConfigInfo loadConfig)
        {
            if (is64Bit)
            {
                return SecurityFeatureStatus.NotApplicable("x64 不使用 SafeSEH");
            }

            if (HasFlag(optionalHeader.DllCharacteristics, DllCharacteristicsNoSeh))
            {
                return SecurityFeatureStatus.NotApplicable("映像声明 NO_SEH");
            }

            if (loadConfig == null)
            {
                return SecurityFeatureStatus.Disabled("缺少 Load Config，未发现 SafeSEH 元数据");
            }

            if (loadConfig.SeHandlerTable != 0 && loadConfig.SeHandlerCount != 0)
            {
                return SecurityFeatureStatus.Enabled("SEHandlerTable/SEHandlerCount 已存在");
            }

            return SecurityFeatureStatus.Disabled("Load Config 存在，但未发现 SafeSEH 表");
        }

        private static SecurityFeatureStatus BuildCfgStatus(OptionalHeader optionalHeader, LoadConfigInfo loadConfig)
        {
            if (!HasFlag(optionalHeader.DllCharacteristics, DllCharacteristicsGuardCf))
            {
                return SecurityFeatureStatus.Disabled("缺少 GUARD_CF 标志");
            }

            if (loadConfig == null)
            {
                return SecurityFeatureStatus.Enabled("DLL Characteristics 启用 GUARD_CF，但缺少 Load Config 细节");
            }

            var hasInstrumentation = (loadConfig.GuardFlags & LoadConfigGuardCfInstrumented) != 0;
            var hasFunctionTable = (loadConfig.GuardFlags & LoadConfigGuardCfFunctionTablePresent) != 0;
            if (hasInstrumentation || hasFunctionTable)
            {
                return SecurityFeatureStatus.Enabled(string.Format("GuardFlags=0x{0:X8}", loadConfig.GuardFlags));
            }

            return SecurityFeatureStatus.Enabled("GUARD_CF 已声明，但 GuardFlags 未暴露常见标志");
        }

        private static SecurityFeatureStatus BuildGsStatus(LoadConfigInfo loadConfig)
        {
            if (loadConfig == null)
            {
                return SecurityFeatureStatus.Unknown("缺少 Load Config，无法基于 SecurityCookie 判断");
            }

            if (loadConfig.SecurityCookie != 0)
            {
                return SecurityFeatureStatus.Enabled(string.Format("SecurityCookie=0x{0:X}", loadConfig.SecurityCookie));
            }

            return SecurityFeatureStatus.Disabled("未发现 SecurityCookie");
        }

        private static List<string> BuildRedFlags(
            IEnumerable<SectionReport> sections,
            SignatureReport signature,
            SecurityFeatureStatus cfg,
            SecurityFeatureStatus gs,
            IEnumerable<SpecialCheckReport> specialChecks)
        {
            var flags = new List<string>();
            if (!string.Equals(signature.Status, "SignedPresent", StringComparison.OrdinalIgnoreCase))
            {
                flags.Add("样本未携带有效 Authenticode 签名。");
            }

            if (sections.Any(section => section.IsExecutable && section.IsWritable))
            {
                flags.Add("存在 RWX 节区，需重点确认是否为壳、自解密逻辑或构建配置异常。");
            }

            if (sections.Any(section => section.Entropy >= 7.2d && section.SizeOfRawData >= 512))
            {
                flags.Add("存在高熵节区，可能与压缩、加密或混淆有关。");
            }

            if (string.Equals(cfg.State, "Disabled", StringComparison.OrdinalIgnoreCase))
            {
                flags.Add("CFG 未启用。");
            }

            if (string.Equals(gs.State, "Disabled", StringComparison.OrdinalIgnoreCase))
            {
                flags.Add("未发现 GS Cookie。");
            }

            foreach (var failedCheck in specialChecks.Where(item => string.Equals(item.Status, "Disabled", StringComparison.OrdinalIgnoreCase)))
            {
                if (string.Equals(failedCheck.Name, "Native Subsystem", StringComparison.OrdinalIgnoreCase))
                {
                    flags.Add("驱动文件未声明 Native 子系统。");
                }
                else if (string.Equals(failedCheck.Name, "Relocations", StringComparison.OrdinalIgnoreCase))
                {
                    flags.Add("未发现重定位目录，ASLR 兼容性可能不足。");
                }
            }

            return flags;
        }

        private static int RvaToFileOffset(uint rva, IList<SectionHeader> sections)
        {
            foreach (var section in sections)
            {
                var mappedSize = Math.Max(section.VirtualSize, section.SizeOfRawData);
                if (rva >= section.VirtualAddress && rva < section.VirtualAddress + mappedSize)
                {
                    return (int)(section.PointerToRawData + (rva - section.VirtualAddress));
                }
            }

            return -1;
        }

        private static bool HasFlag(ushort value, ushort flag)
        {
            return (value & flag) == flag;
        }

        private static string GetMachineName(ushort machine)
        {
            switch (machine)
            {
                case 0x014C:
                    return "x86";
                case 0x8664:
                    return "x64";
                case 0x01C4:
                    return "ARM Thumb-2";
                case 0xAA64:
                    return "ARM64";
                default:
                    return string.Format("0x{0:X4}", machine);
            }
        }

        private static string GetSubsystemName(ushort subsystem)
        {
            switch (subsystem)
            {
                case 1:
                    return "Native";
                case 2:
                    return "Windows GUI";
                case 3:
                    return "Windows CUI";
                case 9:
                    return "Windows CE";
                case 10:
                    return "EFI Application";
                case 11:
                    return "EFI Boot Service";
                case 12:
                    return "EFI Runtime";
                default:
                    return string.Format("0x{0:X4}", subsystem);
            }
        }

        private static string GetImageKind(string filePath, ushort characteristics)
        {
            var extension = Path.GetExtension(filePath) ?? string.Empty;
            if (extension.Equals(".sys", StringComparison.OrdinalIgnoreCase))
            {
                return "Driver";
            }

            if ((characteristics & FileCharacteristicDll) == FileCharacteristicDll ||
                extension.Equals(".dll", StringComparison.OrdinalIgnoreCase))
            {
                return "DLL";
            }

            if (extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
            {
                return "EXE";
            }

            return "PE Image";
        }

        private static double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return 0d;
            }

            var counts = new int[256];
            for (var i = 0; i < data.Length; i++)
            {
                counts[data[i]]++;
            }

            var entropy = 0d;
            for (var i = 0; i < counts.Length; i++)
            {
                if (counts[i] == 0)
                {
                    continue;
                }

                var probability = counts[i] / (double)data.Length;
                entropy -= probability * Math.Log(probability, 2);
            }

            return entropy;
        }

        private static void Ensure(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidDataException(message);
            }
        }

        private static bool HasDirectory(OptionalHeader optionalHeader, int index)
        {
            return index >= 0 &&
                   index < optionalHeader.DataDirectories.Length &&
                   optionalHeader.DataDirectories[index].VirtualAddress != 0 &&
                   optionalHeader.DataDirectories[index].Size != 0;
        }

        private static bool HasSectionPrefix(IEnumerable<SectionHeader> sections, string prefix)
        {
            foreach (var section in sections)
            {
                if (!string.IsNullOrWhiteSpace(section.Name) &&
                    section.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static SpecialCheckReport CreateCheck(string name, bool enabled, string details)
        {
            return new SpecialCheckReport
            {
                Name = name,
                Status = enabled ? "Enabled" : "Disabled",
                Details = details
            };
        }

        private sealed class DosHeader
        {
            public ushort Magic { get; set; }

            public int LfaNew { get; set; }
        }

        private sealed class FileHeader
        {
            public ushort Machine { get; set; }

            public ushort NumberOfSections { get; set; }

            public uint TimeDateStamp { get; set; }

            public uint PointerToSymbolTable { get; set; }

            public uint NumberOfSymbols { get; set; }

            public ushort SizeOfOptionalHeader { get; set; }

            public ushort Characteristics { get; set; }
        }

        private sealed class OptionalHeader
        {
            public ushort Magic { get; set; }

            public ushort Subsystem { get; set; }

            public ulong ImageBase { get; set; }

            public ushort DllCharacteristics { get; set; }

            public DataDirectory[] DataDirectories { get; set; }
        }

        private sealed class DataDirectory
        {
            public uint VirtualAddress { get; set; }

            public uint Size { get; set; }
        }

        private sealed class SectionHeader
        {
            public string Name { get; set; }

            public uint VirtualSize { get; set; }

            public uint VirtualAddress { get; set; }

            public uint SizeOfRawData { get; set; }

            public uint PointerToRawData { get; set; }

            public uint Characteristics { get; set; }
        }

        private sealed class LoadConfigInfo
        {
            public uint Size { get; set; }

            public ulong SecurityCookie { get; set; }

            public ulong SeHandlerTable { get; set; }

            public ulong SeHandlerCount { get; set; }

            public uint GuardFlags { get; set; }
        }

    }
}
