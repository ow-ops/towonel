//! Mesh client: device identity, local state, and the hub control-plane API.

pub mod api;
pub mod client;
pub mod state;

pub use client::{MeshClient, NetmapStream, Poll, StreamEvent};
pub use state::{Enrollment, StateDir};
