//! The network where the zkDpos resides.
//!

// Built-in uses
use std::{fmt, str::FromStr, u32};

// External uses
use serde::{Deserialize, Serialize};

// Workspace uses

// Local uses

/// Network to be used for a zkDpos client.
///
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Network {
    /// Alaya Mainnet.
    Mainnet,
    /// Alaya Testnet.
    Testnet,
    /// Alaya Rinkeby testnet.
    Rinkeby,
    /// Alaya Ropsten testnet.
    Ropsten,
    /// Self-hosted Alaya & zkDpos networks.
    Localhost,
    /// Unknown network type.
    Unknown,
    /// Test network for testkit purposes
    Test,
}

impl FromStr for Network {
    type Err = String;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Ok(match string {
            "mainnet" => Self::Mainnet,
            "testnet" => Self::Testnet,
            "rinkeby" => Self::Rinkeby,
            "ropsten" => Self::Ropsten,
            "localhost" => Self::Localhost,
            "test" => Self::Test,
            another => return Err(another.to_owned()),
        })
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Rinkeby => write!(f, "rinkeby"),
            Self::Ropsten => write!(f, "ropsten"),
            Self::Localhost => write!(f, "localhost"),
            Self::Unknown => write!(f, "unknown"),
            Self::Test => write!(f, "test"),
        }
    }
}

impl Network {
    /// Returns the network chain ID on the Alaya side.
    pub fn chain_id(self) -> u32 {
        match self {
            Network::Mainnet => 201018,
            Network::Testnet => 201030,
            Network::Ropsten => 3,
            Network::Rinkeby => 4,
            Network::Localhost => 9,
            Network::Unknown => panic!("Unknown chain ID"),
            Network::Test => panic!("Test chain ID"),
        }
    }
}
