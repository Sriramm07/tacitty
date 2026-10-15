# The "production database server" in the demo: sshd + PostgreSQL.
# All passwords here are throwaway demo values.
FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server postgresql \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash admin \
 && echo 'admin:Adm1n-Ssh-2026' | chpasswd \
 && echo 'root:R00t-Pr0d-2026' | chpasswd \
 && rm -f /etc/motd /etc/update-motd.d/* \
 && mkdir -p /run/sshd \
 && printf 'PrintMotd no\nPrintLastLog no\nPasswordAuthentication yes\n' \
      > /etc/ssh/sshd_config.d/demo.conf
RUN sed -i 's/^ssl = on/ssl = off/' /etc/postgresql/*/main/postgresql.conf \
 && service postgresql start \
 && su postgres -c "psql -q -c \"ALTER USER postgres PASSWORD 'Pg-Pr0d-2026';\"" \
 && service postgresql stop
CMD service postgresql start >/dev/null && exec /usr/sbin/sshd -D -e
