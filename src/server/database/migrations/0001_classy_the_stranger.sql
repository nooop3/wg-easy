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
  '/usr/sbin/nft ''delete table ip "wg-easy-{{interface}}"'' 2>/dev/null || true; /usr/sbin/nft ''delete table ip6 "wg-easy-{{interface}}"'' 2>/dev/null || true; /usr/sbin/nft ''delete table inet "wg-easy-{{interface}}"'' 2>/dev/null || true; /usr/sbin/nft ''add table ip "wg-easy-{{interface}}"''; /usr/sbin/nft ''add chain ip "wg-easy-{{interface}}" postrouting { type nat hook postrouting priority 100; policy accept; }''; /usr/sbin/nft ''add rule ip "wg-easy-{{interface}}" postrouting ip saddr {{ipv4Cidr}} oifname "{{device}}" masquerade''; /usr/sbin/nft ''add table ip6 "wg-easy-{{interface}}"''; /usr/sbin/nft ''add chain ip6 "wg-easy-{{interface}}" postrouting { type nat hook postrouting priority 100; policy accept; }''; /usr/sbin/nft ''add rule ip6 "wg-easy-{{interface}}" postrouting ip6 saddr {{ipv6Cidr}} oifname "{{device}}" masquerade''; /usr/sbin/nft ''add table inet "wg-easy-{{interface}}"''; /usr/sbin/nft ''add chain inet "wg-easy-{{interface}}" input { type filter hook input priority 0; policy accept; }''; /usr/sbin/nft ''add rule inet "wg-easy-{{interface}}" input udp dport {{port}} accept''; /usr/sbin/nft ''add chain inet "wg-easy-{{interface}}" forward { type filter hook forward priority 0; policy accept; }''; /usr/sbin/nft ''add rule inet "wg-easy-{{interface}}" forward iifname "{{interface}}" accept''; /usr/sbin/nft ''add rule inet "wg-easy-{{interface}}" forward oifname "{{interface}}" accept'';',
  '',
  '/usr/sbin/nft ''delete table ip "wg-easy-{{interface}}"'' 2>/dev/null || true; /usr/sbin/nft ''delete table ip6 "wg-easy-{{interface}}"'' 2>/dev/null || true; /usr/sbin/nft ''delete table inet "wg-easy-{{interface}}"'' 2>/dev/null || true;'
);
--> statement-breakpoint
INSERT INTO `user_configs_table` (`id`, `default_mtu`, `default_persistent_keepalive`, `default_dns`, `default_allowed_ips`, `host`, `port`)
VALUES ('wg0', 1420, 0, '["1.1.1.1","2606:4700:4700::1111"]', '["0.0.0.0/0","::/0"]', '', 51820)
