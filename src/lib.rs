//! `NetzZwergenWacht` core library.
//!
//! Separates validated domain contracts ([`domain`]), Die Zwergenbrigade
//! identity registry ([`brigade`]), bounded external evidence collection
//! ([`collection`]), and deterministic analysers ([`analysis`]).

pub mod analysis;
pub mod brigade;
pub mod collection;
pub mod domain;
