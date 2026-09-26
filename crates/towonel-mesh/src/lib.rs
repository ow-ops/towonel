//! Mesh client: device identity, local state, and the hub control-plane API.

pub mod api;
pub mod client;
pub mod dns;
#[cfg(unix)]
pub mod local;
pub mod node;
pub mod packet;
pub mod peer;
pub mod policy;
pub mod state;
#[cfg(feature = "tun")]
pub mod tun;

pub use client::{MeshClient, NetmapStream, Poll, StreamEvent};
pub use node::{MeshNode, NodeOptions, PeerStatus, Stopped};
pub use state::{Enrollment, StateDir};
