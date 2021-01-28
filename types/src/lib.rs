pub mod message;
pub mod types;

/// delivery data.
#[macro_export]
macro_rules! delivery_split {
    ($data:expr, $length:expr) => {
        if $data.len() < $length {
            $data.clone()
        } else {
            $data[0..$length].to_vec()
        }
    };
}
