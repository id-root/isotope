use std::f32::consts::PI;

pub fn simulate_audio_capture() -> Vec<i16> {
    let sample_rate = 48000;
    let frequency = 440.0;
    let duration_ms = 60;
    let num_samples = (sample_rate * duration_ms / 1000) as usize;

    (0..num_samples)
        .map(|i| (i as f32 * frequency * 2.0 * PI / sample_rate as f32).sin() * 3000.0)
        .map(|x| x as i16)
        .collect()
}
