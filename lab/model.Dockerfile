# CPU-only Ollama runtime with the model baked in, so the model pod needs no egress.
# The upstream image carries ~3.5 GB of GPU libraries; the final stage copies the
# filesystem after they are removed, so they do not end up in any layer.
ARG OLLAMA_VERSION=0.40.16
FROM ollama/ollama:${OLLAMA_VERSION} AS build
# One or more models, space separated, e.g. "qwen3:0.6b qwen3:1.7b".
ARG MODELS=qwen3:0.6b
ENV OLLAMA_MODELS=/models HOME=/tmp
RUN (ollama serve >/tmp/serve.log 2>&1 &) \
 && for i in $(seq 1 60); do ollama list >/dev/null 2>&1 && break; sleep 1; done \
 && for m in $MODELS; do ollama pull "$m"; done \
 && ollama list \
 && rm -rf /usr/lib/ollama/cuda_* /usr/lib/ollama/vulkan* /tmp/* /tmp/.ollama \
 && chown -R 10001:10001 /models

FROM scratch
COPY --from=build / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    OLLAMA_HOST=0.0.0.0:11434 OLLAMA_MODELS=/models HOME=/tmp
USER 10001:10001
EXPOSE 11434
ENTRYPOINT ["/bin/ollama"]
CMD ["serve"]
