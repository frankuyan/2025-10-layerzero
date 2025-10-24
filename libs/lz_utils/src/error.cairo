/// Trait to get the error name for an error code.
/// This trait is intended to be implemented for enum types.
pub trait Error<T> {
    fn name(self: T) -> ByteArray;
    fn prefix() -> ByteArray;
}

/// Generic format function that works with any type implementing Error trait
/// ERROR_CODE::MESSAGE
pub fn format_error<T, +Error<T>, +Drop<T>>(error: T, message: ByteArray) -> ByteArray {
    format!("{}_{}::{}", Error::<T>::prefix(), error.name(), message)
}
