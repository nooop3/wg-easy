PRAGMA journal_mode=WAL;--> statement-breakpoint
INSERT INTO `general_table` (`setup_step`, `session_password`, `session_timeout`, `metrics_prometheus`, `metrics_json`)
VALUES (1, hex(randomblob(256)), 3600, 0, 0);
--> statement-breakpoint
INSERT INTO `interfaces_table` (`name`, `device`, `port`, `private_key`, `public_key`, `ipv4_cidr`, `ipv6_cidr`, `mtu`, `enabled`)
VALUES ('wg0', 'eth0', 51820, '---default---', '---default---', '10.8.0.0/24', 'fdcc:ad94:bacf:61a4::cafe:0/112', 1420, 1);
--> statement-breakpoint
INSERT INTO `hooks_table` (`id`, `pre_up`, `post_up`, `pre_down`, `post_down`)
VALUES (
  'wg0',
  '',
  '/usr/sbin/iptables-nft -w -t nat -C POSTROUTING -s {{ipv4Cidr}} -j MASQUERADE 2>/dev/null || /usr/sbin/iptables-nft -w -t nat -A POSTROUTING -s {{ipv4Cidr}} -j MASQUERADE; /usr/sbin/iptables-nft -w -C INPUT -p udp -m udp --dport {{port}} -j ACCEPT 2>/dev/null || /usr/sbin/iptables-nft -w -A INPUT -p udp -m udp --dport {{port}} -j ACCEPT; /usr/sbin/iptables-nft -w -C FORWARD -i {{interface}} -j ACCEPT 2>/dev/null || /usr/sbin/iptables-nft -w -A FORWARD -i {{interface}} -j ACCEPT; /usr/sbin/iptables-nft -w -C FORWARD -o {{interface}} -j ACCEPT 2>/dev/null || /usr/sbin/iptables-nft -w -A FORWARD -o {{interface}} -j ACCEPT; /usr/sbin/ip6tables-nft -w -t nat -C POSTROUTING -s {{ipv6Cidr}} -j MASQUERADE 2>/dev/null || /usr/sbin/ip6tables-nft -w -t nat -A POSTROUTING -s {{ipv6Cidr}} -j MASQUERADE; /usr/sbin/ip6tables-nft -w -C INPUT -p udp -m udp --dport {{port}} -j ACCEPT 2>/dev/null || /usr/sbin/ip6tables-nft -w -A INPUT -p udp -m udp --dport {{port}} -j ACCEPT; /usr/sbin/ip6tables-nft -w -C FORWARD -i {{interface}} -j ACCEPT 2>/dev/null || /usr/sbin/ip6tables-nft -w -A FORWARD -i {{interface}} -j ACCEPT; /usr/sbin/ip6tables-nft -w -C FORWARD -o {{interface}} -j ACCEPT 2>/dev/null || /usr/sbin/ip6tables-nft -w -A FORWARD -o {{interface}} -j ACCEPT;',
  '',
  'while /usr/sbin/iptables-nft -w -t nat -D POSTROUTING -s {{ipv4Cidr}} -j MASQUERADE 2>/dev/null; do :; done; while /usr/sbin/iptables-nft -w -D INPUT -p udp -m udp --dport {{port}} -j ACCEPT 2>/dev/null; do :; done; while /usr/sbin/iptables-nft -w -D FORWARD -i {{interface}} -j ACCEPT 2>/dev/null; do :; done; while /usr/sbin/iptables-nft -w -D FORWARD -o {{interface}} -j ACCEPT 2>/dev/null; do :; done; while /usr/sbin/ip6tables-nft -w -t nat -D POSTROUTING -s {{ipv6Cidr}} -j MASQUERADE 2>/dev/null; do :; done; while /usr/sbin/ip6tables-nft -w -D INPUT -p udp -m udp --dport {{port}} -j ACCEPT 2>/dev/null; do :; done; while /usr/sbin/ip6tables-nft -w -D FORWARD -i {{interface}} -j ACCEPT 2>/dev/null; do :; done; while /usr/sbin/ip6tables-nft -w -D FORWARD -o {{interface}} -j ACCEPT 2>/dev/null; do :; done;'
);
--> statement-breakpoint
INSERT INTO `user_configs_table` (`id`, `default_mtu`, `default_persistent_keepalive`, `default_dns`, `default_allowed_ips`, `host`, `port`)
VALUES ('wg0', 1420, 0, '["1.1.1.1","2606:4700:4700::1111"]', '["0.0.0.0/0","::/0"]', '', 51820)
