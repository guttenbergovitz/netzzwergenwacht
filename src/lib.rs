//! `NetzZwergenWacht` core library.
//!
//! Separates validated domain contracts ([`domain`]), Die Zwergenbrigade
//! identity registry ([`brigade`]), configuration and policy gates ([`config`]),
//! bounded external evidence collection ([`collection`]), deterministic
//! analysers ([`analysis`]), and audit history persistence ([`persistence`]).

pub mod analysis;
pub mod brigade;
pub mod collection;
pub mod config;
pub mod domain;
pub mod persistence;
