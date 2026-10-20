macro_rules! u16_enum {
    ($(#[$m:meta])* $name:ident { $($var:ident = $val:expr),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $($var,)+
            /// A value without a named variant.
            Unknown(u16),
        }

        impl From<u16> for $name {
            fn from(v: u16) -> Self {
                match v {
                    $($val => Self::$var,)+
                    other => Self::Unknown(other),
                }
            }
        }

        impl From<$name> for u16 {
            fn from(v: $name) -> u16 {
                match v {
                    $($name::$var => $val,)+
                    $name::Unknown(other) => other,
                }
            }
        }
    };
}

u16_enum!(
    /// Resource record TYPE (and QTYPE).
    RecordType {
        A = 1, Ns = 2, Cname = 5, Soa = 6, Ptr = 12, Mx = 15, Txt = 16, Aaaa = 28, Srv = 33,
        Opt = 41, Ds = 43, Rrsig = 46, Nsec = 47, Dnskey = 48, Nsec3 = 50, Nsec3param = 51,
        Cds = 59, Cdnskey = 60, Svcb = 64, Https = 65, Caa = 257, Any = 255,
    }
);

u16_enum!(
    /// Resource record CLASS (and QCLASS).
    Class { In = 1, Ch = 3, Any = 255 }
);

u16_enum!(
    /// Response code (the low four bits live in the header, the rest in EDNS).
    Rcode {
        NoError = 0, FormErr = 1, ServFail = 2, NxDomain = 3, NotImp = 4, Refused = 5,
        BadVers = 16,
    }
);

/// Header OPCODE (four bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    /// A value without a named variant.
    Unknown(u8),
}

impl From<u8> for Opcode {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            other => Self::Unknown(other),
        }
    }
}

impl From<Opcode> for u8 {
    fn from(v: Opcode) -> u8 {
        match v {
            Opcode::Query => 0,
            Opcode::IQuery => 1,
            Opcode::Status => 2,
            Opcode::Notify => 4,
            Opcode::Update => 5,
            Opcode::Unknown(other) => other,
        }
    }
}
