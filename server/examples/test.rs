extern crate tokio;

extern crate server;

use tokio::prelude::Future;

fn main() {
    tokio::run(
        server::Server::new()
            .unwrap()
            .map_err(|error| println!("Server error: {:?}", error))
    );
}
