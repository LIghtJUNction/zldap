mod allocations;

use std::hint::black_box;
use std::time::Instant;
use zldap::{ber::Frame, Message, ParseLimits};
use zldap_comparison::{
    corpus::{self, Case},
    encoding, oracle,
    semantics::{self, Digest},
};

#[cfg(feature = "count-allocations")]
#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const DEPTH: usize = 32;

fn decode_z(case: &Case, workspace: &mut [Frame], scan: bool) {
    let mut input = black_box(case.wire.as_slice());
    while !input.is_empty() {
        let (message, used) = Message::parse_prefix(input, ParseLimits::default(), workspace)
            .expect("zldap benchmark fixture");
        if scan {
            let mut digest = Digest::default();
            semantics::zldap(&message, &mut digest);
            black_box(digest.0);
        } else {
            black_box(message);
        }
        input = &input[used..];
    }
}

fn decode_oracle(case: &Case, scan: bool) {
    let mut input = black_box(case.wire.as_slice());
    while !input.is_empty() {
        let (message, used) =
            oracle::parse_prefix(input, DEPTH + 1).expect("oracle benchmark fixture");
        if scan {
            let mut digest = Digest::default();
            semantics::kanidm(&message, &mut digest);
            black_box(digest.0);
        } else {
            black_box(&message);
        }
        input = &input[used..];
    }
}

fn paired(
    case: &Case,
    phase: &str,
    iterations: usize,
    sample_count: usize,
    mut z: impl FnMut(),
    mut k: impl FnMut(),
) {
    let per_sample = (iterations / case.messages)
        .max(1)
        .min((64 * 1024 * 1024 / case.wire.len().max(1)).max(1));
    for _ in 0..100 {
        z();
        k();
    }
    if cfg!(feature = "count-allocations") {
        let (z_calls, z_peak) = allocations::measure(z);
        let (k_calls, k_peak) = allocations::measure(k);
        report(case, phase, "zldap", vec![f64::NAN], z_calls, z_peak);
        report(case, phase, "ldap3_proto", vec![f64::NAN], k_calls, k_peak);
        return;
    }
    let mut z_samples = Vec::with_capacity(sample_count);
    let mut k_samples = Vec::with_capacity(sample_count);
    for sample in 0..sample_count {
        if sample % 2 == 0 {
            z_samples.push(time(&mut z, per_sample, case.messages));
            k_samples.push(time(&mut k, per_sample, case.messages));
        } else {
            k_samples.push(time(&mut k, per_sample, case.messages));
            z_samples.push(time(&mut z, per_sample, case.messages));
        }
    }
    report(case, phase, "zldap", z_samples, 0, 0);
    report(case, phase, "ldap3_proto", k_samples, 0, 0);
}

fn stats(mut samples: Vec<f64>) -> (f64, f64, f64) {
    samples.sort_by(f64::total_cmp);
    (
        samples[samples.len() / 2],
        samples[0],
        samples[samples.len() - 1],
    )
}

fn time(mut operation: impl FnMut(), iterations: usize, messages: usize) -> f64 {
    let start = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    start.elapsed().as_secs_f64() * 1e9 / (iterations * messages) as f64
}

fn report(
    case: &Case,
    phase: &str,
    implementation: &str,
    samples: Vec<f64>,
    calls: usize,
    peak: usize,
) {
    let (median, minimum, maximum) = stats(samples);
    let bytes_per_message = case.wire.len() as f64 / case.messages as f64;
    let (calls, peak) = if cfg!(feature = "count-allocations") {
        (
            format!("{:.3}", calls as f64 / case.messages as f64),
            peak.to_string(),
        )
    } else {
        (String::new(), String::new())
    };
    println!(
        "{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.6},{},{}",
        case.name,
        phase,
        implementation,
        case.wire.len(),
        case.messages,
        median,
        minimum,
        maximum,
        1e9 / median,
        median / bytes_per_message,
        calls,
        peak,
    );
}

fn errors() {
    println!("case,zldap_error,kanidm_error");
    for case in corpus::malformed() {
        let mut frames = [Frame::EMPTY; DEPTH];
        let mut limits = ParseLimits::default();
        if case.name == "oversized_value" {
            limits.max_message_len = 32_768;
        }
        let z = Message::parse(&case.wire, limits, &mut frames)
            .map(|_| "accepted".to_owned())
            .unwrap_or_else(|e| format!("{:?}", e.kind));
        // The LdapCodec checks size after BER parsing; reproduce that ordering.
        let k = oracle::parse_exact_limited(&case.wire, DEPTH + 1, limits.max_message_len)
            .map(|_| "accepted".to_owned())
            .unwrap_or_else(|e| format!("{e:?}"));
        println!("{},{},{}", case.name, z, k);
    }
}

fn main() {
    let mut iterations = 50_000usize;
    let mut sample_count = 7usize;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iterations" => {
                iterations = args
                    .next()
                    .expect("iteration count")
                    .parse()
                    .expect("integer iterations")
            }
            "--samples" => {
                sample_count = args
                    .next()
                    .expect("sample count")
                    .parse()
                    .expect("integer samples")
            }
            "--report-errors" => {
                errors();
                return;
            }
            _ => panic!("unknown argument {arg}"),
        }
    }
    assert!(iterations > 0 && sample_count > 0);
    eprintln!("zldap comparison; ldap3_proto=0.9.0; ldap3_lber=0.9.0; strict=true");
    eprintln!(
        "samples={sample_count}; target_messages_per_sample={iterations}; limits={:?}",
        ParseLimits::default()
    );
    eprintln!(
        "count-allocations={}; instrumented builds report memory only; peak bytes exclude caller input/workspace", cfg!(feature = "count-allocations")
    );
    println!("case,phase,implementation,bytes,messages,median_ns_per_message,min_ns_per_message,max_ns_per_message,messages_per_second,ns_per_byte,allocations_per_message,peak_live_heap_bytes");
    for case in corpus::corpus() {
        let mut workspace = [Frame::EMPTY; DEPTH];
        for scan in [false, true] {
            paired(
                &case,
                if scan { "decode_and_scan" } else { "decode" },
                iterations,
                sample_count,
                || decode_z(&case, &mut workspace, scan),
                || decode_oracle(&case, scan),
            );
        }
        if case.messages == 1 {
            let message =
                Message::parse(&case.wire, ParseLimits::default(), &mut workspace).unwrap();
            let reference = oracle::parse_exact(&case.wire, DEPTH + 1).unwrap();
            encoding::with_input(message, |input| {
                let mut z_buffer = vec![0; input.encoded_len().unwrap()];
                let mut k_buffer = bytes::BytesMut::with_capacity(z_buffer.len());
                paired(
                    &case,
                    "encode_reuse",
                    iterations,
                    sample_count,
                    || {
                        let len = black_box(&input).encode(black_box(&mut z_buffer)).unwrap();
                        black_box(&z_buffer[..len]);
                    },
                    || {
                        k_buffer.clear();
                        oracle::encode(black_box(&reference).clone(), &mut k_buffer);
                        black_box(k_buffer.as_ref());
                    },
                );
            });
        }
    }
    for case in corpus::malformed() {
        let mut workspace = [Frame::EMPTY; DEPTH];
        let mut limits = ParseLimits::default();
        if case.name == "oversized_value" {
            limits.max_message_len = 32_768;
        }
        paired(
            &case,
            "rejection_policy",
            iterations,
            sample_count,
            || {
                black_box(Message::parse(black_box(&case.wire), limits, &mut workspace).is_err());
            },
            || {
                black_box(
                    oracle::parse_exact_limited(
                        black_box(&case.wire),
                        DEPTH + 1,
                        limits.max_message_len,
                    )
                    .is_err(),
                );
            },
        );
    }
}
