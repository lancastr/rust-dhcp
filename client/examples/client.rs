extern crate tokio;
extern crate eui48;
extern crate rand;

extern crate client;

//use std::net::Ipv4Addr;

use eui48::MacAddress;
use tokio::prelude::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let client_id = args.get(1).unwrap_or(&"666".to_owned()).parse().unwrap_or(666);

    let future = client::Client::new(
        None,//Some(Ipv4Addr::new(192,168,0,12)),
        client_id,//rand::random::<u32>(),
        MacAddress::new([0x01,0x02,0x03,0x04,0x05,0x06]),
    )
        .unwrap()
        .map_err(|error| println!("{}", error))
        .map(|result| match result {
            Some((message, _addr)) => println!("{}", message),
            None => println!("None"),
        });
    tokio::run(future);

//    let future = future::ok::<i32, ()>(match socket.start_send((discover, server_addr)) {
//        Ok(AsyncSink::Ready) => {
//            match socket.poll_complete() {
//                Ok(Async::Ready(_)) => 1,
//                Ok(Async::NotReady) => 2,
//                Err(_) => 3,
//            }
//        },
//        Ok(AsyncSink::NotReady(_)) => 4,
//        Err(_) => 5,
//    });
}