//! DHCP option tags module.

/// DHCP options codes.
#[derive(Debug, Clone, Copy)]
pub enum OptionTag {
    Unknown = -1,
    Pad = 0,

    /*
    RFC 2132
    */
    // RFC 1497 Vendor Extensions (RFC 2132 §3)
    SubnetMask,
    TimeOffset,
    Routers,
    TimeServers,
    NameServers,
    DomainNameServers,
    LogServers,
    QuotesServers,
    LprServers,
    ImpressServers,
    RlpServers,
    Hostname,
    BootFileSize,
    MeritDumpFile,
    DomainName,
    SwapServer,
    RootPath,
    ExtensionsPath,
    // IP Layer Parameters per Host (RFC 2132 §4)
    ForwardOnOff,
    NonLocalSourceRouteOnOff,
    PolicyFilters,
    MaxDatagramReassemblySize,
    DefaultIpTtl,
    MtuTimeout,
    MtuPlateau,
    // IP Layer Parameters per Interface (RFC 2132 §5)
    MtuInterface,
    MtuSubnet,
    BroadcastAddress,
    MaskRecovery,
    MaskSupplier,
    PerformRouterDiscovery,
    RouterSolicitationAddress,
    StaticRoutes,
    // Link Layer Parameters per Interface (RFC 2132 §6)
    TrailerEncapsulation,
    ArpTimeout,
    EthernetEncapsulation,
    // TCP Default TTL Option (RFC 2132 §7)
    DefaultTcpTtl,
    KeepaliveTime,
    KeepaliveData,
    // Application and Service Parameters (RFC 2132 §8)
    NisDomain,
    NisServers,
    NtpServers,
    VendorSpecific,
    NetbiosNameServers,
    NetbiosDistributionServers,
    NetbiosNodeType,
    NetbiosScope,
    XWindowFontServers,
    XWindowManagerServers,
    // DHCP Extensions (RFC 2132 §9)
    AddressRequest,
    AddressTime,
    Overload,
    DhcpMessageType,
    DhcpServerId,
    ParameterList,
    DhcpMessage,
    DhcpMaxMessageSize,
    RenewalTime,
    RebindingTime,
    ClassId,
    ClientId,

    /*
    RFC 2242
    */
    NetwareIpDomain,
    NetwareIpOption,

    /*
    RFC 2132 (continuation)
    */
    // Application and Service Parameters (RFC 2132 §8) (continuation)
    NisDomainName,
    NisServerAddress,
    ServerName,
    BootfileName,
    HomeAgentAddresses,
    SmtpServers,
    Pop3Servers,
    NntpServers,
    WwwServers,
    FingerServers,
    IrcServers,
    StreetTalkServers,
    StdaServers,

    /*
    RFC 3442 (The Classless Static Route Option)
    */
    ClasslessStaticRoutes = 121,

    End = 255,
}

impl From<u8> for OptionTag {
    fn from(value: u8) -> Self {
        use self::OptionTag::*;
        match value {
            0 => Pad,
            1 => SubnetMask,
            2 => TimeOffset,
            3 => Routers,
            4 => TimeServers,
            5 => NameServers,
            6 => DomainNameServers,
            7 => LogServers,
            8 => QuotesServers,
            9 => LprServers,
            10 => ImpressServers,
            11 => RlpServers,
            12 => Hostname,
            13 => BootFileSize,
            14 => MeritDumpFile,
            15 => DomainName,
            16 => SwapServer,
            17 => RootPath,
            18 => ExtensionsPath,
            19 => ForwardOnOff,
            20 => NonLocalSourceRouteOnOff,
            21 => PolicyFilters,
            22 => MaxDatagramReassemblySize,
            23 => DefaultIpTtl,
            24 => MtuTimeout,
            25 => MtuPlateau,
            26 => MtuInterface,
            27 => MtuSubnet,
            28 => BroadcastAddress,
            29 => MaskRecovery,
            30 => MaskSupplier,
            31 => PerformRouterDiscovery,
            32 => RouterSolicitationAddress,
            33 => StaticRoutes,
            34 => TrailerEncapsulation,
            35 => ArpTimeout,
            36 => EthernetEncapsulation,
            37 => DefaultTcpTtl,
            38 => KeepaliveTime,
            39 => KeepaliveData,
            40 => NisDomain,
            41 => NisServers,
            42 => NtpServers,
            43 => VendorSpecific,
            44 => NetbiosNameServers,
            45 => NetbiosDistributionServers,
            46 => NetbiosNodeType,
            47 => NetbiosScope,
            48 => XWindowFontServers,
            49 => XWindowManagerServers,
            50 => AddressRequest,
            51 => AddressTime,
            52 => Overload,
            53 => DhcpMessageType,
            54 => DhcpServerId,
            55 => ParameterList,
            56 => DhcpMessage,
            57 => DhcpMaxMessageSize,
            58 => RenewalTime,
            59 => RebindingTime,
            60 => ClassId,
            61 => ClientId,
            62 => NetwareIpDomain,
            63 => NetwareIpOption,
            64 => NisDomainName,
            65 => NisServerAddress,
            66 => ServerName,
            67 => BootfileName,
            68 => HomeAgentAddresses,
            69 => SmtpServers,
            70 => Pop3Servers,
            71 => NntpServers,
            72 => WwwServers,
            73 => FingerServers,
            74 => IrcServers,
            75 => StreetTalkServers,
            76 => StdaServers,

            121 => ClasslessStaticRoutes,

            255 => End,
            _ => Unknown,
        }
    }
}
