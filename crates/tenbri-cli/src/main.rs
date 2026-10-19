//! The `tenbri` binary. Placeholder until the CLI lands.

fn main() {
    println!("tenbri {}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    #[test]
    fn has_a_version() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }
}
