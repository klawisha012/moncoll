// OpenTelemetry web-трассировка. Импортируется ПЕРВЫМ в main.tsx, чтобы
// fetch-инструментация перехватила все вызовы /api/* до их первого использования.
//
// Спаны уходят OTLP/HTTP на same-origin /v1/traces (nginx проксирует на
// otel-collector → ClickHouse), поэтому CORS не нужен и коллектор не светится
// наружу. W3C traceparent добавляется к same-origin fetch автоматически —
// так фронтовые спаны связываются со спанами angie и gobackend в одну трассу.
//
// Трассировка включается только если задан VITE_OTEL (build-time флаг), иначе
// модуль — no-op и в бандл почти ничего не тянет. По умолчанию в dev включено.
import { WebTracerProvider, BatchSpanProcessor } from "@opentelemetry/sdk-trace-web";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { ATTR_SERVICE_NAME } from "@opentelemetry/semantic-conventions";
import { registerInstrumentations } from "@opentelemetry/instrumentation";
import { FetchInstrumentation } from "@opentelemetry/instrumentation-fetch";

// Включено, если VITE_OTEL !== "off". В dev по умолчанию включаем.
const enabled = import.meta.env.VITE_OTEL !== "off";

if (enabled) {
  const provider = new WebTracerProvider({
    resource: resourceFromAttributes({ [ATTR_SERVICE_NAME]: "waf-frontend" }),
    spanProcessors: [
      new BatchSpanProcessor(new OTLPTraceExporter({ url: "/v1/traces" })),
    ],
  });
  // register() ставит дефолтный context manager и W3C-пропагатор.
  provider.register();

  registerInstrumentations({
    instrumentations: [
      // Спан на каждый fetch. traceparent добавляется к same-origin запросам
      // (наш /api) автоматически; cross-origin намеренно НЕ трогаем, чтобы не
      // утекал заголовок на сторонние домены.
      new FetchInstrumentation({ clearTimingResources: true }),
    ],
  });
}
