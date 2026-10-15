# The "laptop" in the demo: VHS plus an ssh client.
FROM ghcr.io/charmbracelet/vhs:v0.10.0
# The image's apt sources say "stable", which has moved on since it was
# built; pin them to the release it actually is.
RUN sed -i -E 's/\bstable(-updates|-security)?\b/bookworm\1/g' \
      /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; \
    apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*
