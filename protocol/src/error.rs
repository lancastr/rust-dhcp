//! Error module

#[derive(Fail, Debug)]
/// Returned by `Message::validate`.
pub enum Error {
    #[fail(display = "Validation error")]
    Validation,
}