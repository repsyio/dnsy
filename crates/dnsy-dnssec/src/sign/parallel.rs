//! Order-preserving parallel map over `std::thread::scope`, bounded by the available cores.

use std::num::NonZeroUsize;
use std::thread;

/// Items per worker below which another thread costs more than it saves.
const MIN_CHUNK: usize = 512;

/// The worker bound: the cores this process may use.
pub(crate) fn cores() -> usize {
    thread::available_parallelism().map_or(1, NonZeroUsize::get)
}

/// Applies `f` to every item and returns the results in input order, on at most `workers`
/// threads (`1` runs on the calling thread). Small inputs stay on the calling thread; larger
/// ones are split into equal chunks.
pub(crate) fn map_with<T, R>(items: Vec<T>, workers: usize, f: impl Fn(T) -> R + Sync) -> Vec<R>
where
    T: Send,
    R: Send,
{
    let workers = workers.min(items.len().div_ceil(MIN_CHUNK)).max(1);
    if workers == 1 {
        return items.into_iter().map(f).collect();
    }
    let total = items.len();
    let size = total.div_ceil(workers);
    // Chunks are cut from the back and the input is shrunk after each cut, so the items are
    // never held twice.
    let mut items = items;
    let mut chunks = Vec::with_capacity(workers);
    while !items.is_empty() {
        let tail = items.split_off(items.len().saturating_sub(size));
        items.shrink_to_fit();
        chunks.push(tail);
    }
    chunks.reverse();
    let f = &f;
    thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| scope.spawn(move || chunk.into_iter().map(f).collect::<Vec<R>>()))
            .collect();
        let mut out = Vec::with_capacity(total);
        for handle in handles {
            match handle.join() {
                Ok(mut results) => out.append(&mut results),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_input_order_across_workers() {
        let items: Vec<u32> = (0..5000).collect();
        let out = map_with(items.clone(), 4, |i| i * 2);
        assert_eq!(out, items.iter().map(|i| i * 2).collect::<Vec<_>>());
    }

    #[test]
    fn uneven_splits_keep_every_item_in_order() {
        for (len, workers) in [(5001, 7), (1025, 2), (2049, 3)] {
            let items: Vec<usize> = (0..len).collect();
            assert_eq!(map_with(items.clone(), workers, |i| i), items);
        }
    }

    #[test]
    fn small_inputs_and_empty_input_work() {
        assert_eq!(map_with(vec![1, 2, 3], 8, |i| i + 1), vec![2, 3, 4]);
        assert_eq!(map_with(Vec::<u8>::new(), 8, |i| i), Vec::<u8>::new());
    }
}
