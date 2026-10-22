FROM php:8.5.11-apache

# Vulnerable-by-design lab target for CVE-2026-109618 / CVE-2026-109619.
# Pin the base so a future tag bump can't swap in the fixed release.

# Apache prefork is default in this image; make sure it stays that way
RUN a2dismod mpm_event 2>/dev/null; a2enmod mpm_prefork 2>/dev/null; true

# Both exploit doors:
#   /remote_app.php  C: branch (Serializable gadget class shipped by the app)
#   /enum.php        E: branch (enum-autoload door, no app gadget class)
COPY remote_app.php        /var/www/html/remote_app.php
COPY remote_app_enum.php   /var/www/html/enum.php
COPY check.php               /var/www/html/check.php

# TLS front (self-signed) so the https:// chains can be exercised too
RUN a2enmod ssl && a2ensite default-ssl \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
      -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
      -out    /etc/ssl/certs/ssl-cert-snakeoil.pem \
      -subj "/CN=php2shell-lab" 2>/dev/null

# Writable DocumentRoot (webshell deployment phase) + enough prefork workers
# to survive the crash-oracle probing
RUN chmod o+w /var/www/html \
 && printf '\nMaxRequestWorkers 256\nServerLimit 256\nStartServers 16\nMinSpareServers 8\nMaxSpareServers 32\n' >> /etc/apache2/apache2.conf

EXPOSE 80 443
