use std::sync::OnceLock;

use anyhow::Result;
use opentelemetry::{
    global, metrics::Counter, trace::TracerProvider as _, InstrumentationScope, KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::{PeriodicReader, SdkMeterProvider},
    runtime,
    trace::{RandomIdGenerator, Sampler, TracerProvider},
    Resource,
};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

struct Metrics {
    request: Counter<u64>,
    blocked: Counter<u64>,
    timeout: Counter<u64>,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

pub fn increment_request(host: &str) {
    if let Some(m) = METRICS.get() {
        m.request
            .add(1, &[KeyValue::new("host", host.to_string())]);
    }
}

pub fn increment_blocked(host: &str, reason: &str) {
    if let Some(m) = METRICS.get() {
        m.blocked.add(
            1,
            &[
                KeyValue::new("host", host.to_string()),
                KeyValue::new("reason", reason.to_string()),
            ],
        );
    }
}

pub fn increment_timeout(host: &str) {
    if let Some(m) = METRICS.get() {
        m.timeout
            .add(1, &[KeyValue::new("host", host.to_string())]);
    }
}

pub fn init_telemetry() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json_logs = std::env::var("AEGIS_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "aegis-proxy".to_string());

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

    if let Some(endpoint) = endpoint {
        let resource = Resource::new([KeyValue::new("service.name", service_name.clone())]);

        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint.clone())
            .build()?;

        let tracer_provider = TracerProvider::builder()
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                1.0,
            ))))
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(resource.clone())
            .with_batch_exporter(span_exporter, runtime::Tokio)
            .build();

        let tracer = tracer_provider
            .tracer_with_scope(InstrumentationScope::builder(service_name).build());
        global::set_tracer_provider(tracer_provider);

        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;
        let reader = PeriodicReader::builder(metric_exporter, runtime::Tokio).build();
        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(reader)
            .build();
        global::set_meter_provider(meter_provider);
        let meter = global::meter("aegis-proxy");
        let _ = METRICS.set(Metrics {
            request: meter.u64_counter("aegis.proxy.request").build(),
            blocked: meter.u64_counter("aegis.proxy.blocked").build(),
            timeout: meter.u64_counter("aegis.proxy.timeout").build(),
        });

        let init_result = if json_logs {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .try_init()
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer())
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .try_init()
        };
        if let Err(err) = init_result {
            return Err(anyhow::anyhow!(err.to_string()));
        }
    } else {
        let init_result = if json_logs {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .try_init()
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer())
                .try_init()
        };
        if let Err(err) = init_result {
            return Err(anyhow::anyhow!(err.to_string()));
        }
    }

    Ok(())
}
