//! `NetzZwergenWacht` core library.
//!
//! Separates validated domain contracts ([`domain`]), Die Zwergenbrigade
//! identity registry ([`brigade`]), configuration and policy gates ([`config`]),
//! bounded external evidence collection ([`collection`]), deterministic
//! analysers ([`analysis`]), and audit history persistence ([`persistence`]).

pub mod adapters;
pub mod analysis;
pub mod brigade;
pub mod collection;
pub mod config;
pub mod credentials;
pub mod discovery;
pub mod doctor;
pub mod domain;
pub mod events;
pub mod intelligence;
pub mod investigation;
pub mod patrol;
pub mod persistence;
pub mod tui;
