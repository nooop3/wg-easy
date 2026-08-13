import { drizzle } from 'drizzle-orm/libsql';
import { migrate as drizzleMigrate } from 'drizzle-orm/libsql/migrator';
import { createClient } from '@libsql/client';
import { createDebug } from 'obug';
import { eq } from 'drizzle-orm';

import { GeneralService } from '#db/repositories/general/service';
import { UserService } from '#db/repositories/user/service';
import { UserConfigService } from '#db/repositories/userConfig/service';
import { InterfaceService } from '#db/repositories/interface/service';
import { HooksService } from '#db/repositories/hooks/service';
import { OneTimeLinkService } from '#db/repositories/oneTimeLink/service';
import { ClientService } from '#db/repositories/client/service';
import * as schema from '#db/schema';
import { WG_ENV, WG_INITIAL_ENV } from '#server/utils/config';

const DB_DEBUG = createDebug('Database');

const client = createClient({ url: 'file:/etc/wireguard/wg-easy.db' });
const db = drizzle({ client, schema });

export async function connect() {
  await migrate();
  await normalizeInterfaceName(db);
  const dbService = new DBService(db);

  if (WG_INITIAL_ENV.ENABLED) {
    await initialSetup(dbService);
  }

  if (WG_ENV.DISABLE_IPV6) {
    DB_DEBUG('Warning: Disabling IPv6...');
    await disableIpv6(db);
  }

  return dbService;
}

class DBService {
  clients: ClientService;
  general: GeneralService;
  users: UserService;
  userConfigs: UserConfigService;
  interfaces: InterfaceService;
  hooks: HooksService;
  oneTimeLinks: OneTimeLinkService;

  constructor(db: DBType) {
    this.clients = new ClientService(db);
    this.general = new GeneralService(db);
    this.users = new UserService(db);
    this.userConfigs = new UserConfigService(db);
    this.interfaces = new InterfaceService(db);
    this.hooks = new HooksService(db);
    this.oneTimeLinks = new OneTimeLinkService(db);
  }
}

export type DBType = typeof db;
export type DBServiceType = DBService;

async function migrate() {
  try {
    DB_DEBUG('Migrating database...');
    await drizzleMigrate(db, {
      migrationsFolder: './server/database/migrations',
    });
    DB_DEBUG('Migration complete');
  } catch (e) {
    if (e instanceof Error) {
      DB_DEBUG('Failed to migrate database:', e.message);
    }
    throw e;
  }
}

async function initialSetup(db: DBServiceType) {
  const setup = await db.general.getSetupStep();

  if (setup.done) {
    DB_DEBUG('Setup already done. Skiping initial setup.');
    return;
  }

  if (WG_INITIAL_ENV.IPV4_CIDR && WG_INITIAL_ENV.IPV6_CIDR) {
    DB_DEBUG('Setting initial CIDR...');
    await db.interfaces.updateCidr({
      ipv4Cidr: WG_INITIAL_ENV.IPV4_CIDR,
      ipv6Cidr: WG_INITIAL_ENV.IPV6_CIDR,
    });
  }

  if (WG_INITIAL_ENV.DNS) {
    DB_DEBUG('Setting initial DNS...');
    await db.userConfigs.update({
      defaultDns: WG_INITIAL_ENV.DNS,
    });
  }

  if (WG_INITIAL_ENV.ALLOWED_IPS) {
    DB_DEBUG('Setting initial Allowed IPs...');
    await db.userConfigs.update({
      defaultAllowedIps: WG_INITIAL_ENV.ALLOWED_IPS,
    });
  }

  if (
    WG_INITIAL_ENV.USERNAME &&
    WG_INITIAL_ENV.PASSWORD &&
    WG_INITIAL_ENV.HOST &&
    WG_INITIAL_ENV.PORT
  ) {
    DB_DEBUG('Creating initial user...');
    await db.users.create(WG_INITIAL_ENV.USERNAME, WG_INITIAL_ENV.PASSWORD);

    DB_DEBUG('Setting initial host and port...');
    await db.userConfigs.updateHostPort(
      WG_INITIAL_ENV.HOST,
      WG_INITIAL_ENV.PORT
    );

    await db.general.setSetupStep(0);
  }
}

const defaultNftPostUp =
  '/usr/sbin/nft \'delete table ip "wg-easy-{{interface}}"\' 2>/dev/null || true' +
  '; /usr/sbin/nft \'delete table ip6 "wg-easy-{{interface}}"\' 2>/dev/null || true' +
  '; /usr/sbin/nft \'delete table inet "wg-easy-{{interface}}"\' 2>/dev/null || true' +
  '; /usr/sbin/nft \'add table ip "wg-easy-{{interface}}"\' ' +
  '; /usr/sbin/nft \'add chain ip "wg-easy-{{interface}}" postrouting { type nat hook postrouting priority 100; policy accept; }\'' +
  '; /usr/sbin/nft \'add rule ip "wg-easy-{{interface}}" postrouting ip saddr {{ipv4Cidr}} oifname "{{device}}" masquerade\'' +
  '; /usr/sbin/nft \'add table ip6 "wg-easy-{{interface}}"\' ' +
  '; /usr/sbin/nft \'add chain ip6 "wg-easy-{{interface}}" postrouting { type nat hook postrouting priority 100; policy accept; }\'' +
  '; /usr/sbin/nft \'add rule ip6 "wg-easy-{{interface}}" postrouting ip6 saddr {{ipv6Cidr}} oifname "{{device}}" masquerade\'' +
  '; /usr/sbin/nft \'add table inet "wg-easy-{{interface}}"\' ' +
  '; /usr/sbin/nft \'add chain inet "wg-easy-{{interface}}" input { type filter hook input priority 0; policy accept; }\'' +
  '; /usr/sbin/nft \'add rule inet "wg-easy-{{interface}}" input udp dport {{port}} accept\'' +
  '; /usr/sbin/nft \'add chain inet "wg-easy-{{interface}}" forward { type filter hook forward priority 0; policy accept; }\'' +
  '; /usr/sbin/nft \'add rule inet "wg-easy-{{interface}}" forward iifname "{{interface}}" accept\'' +
  '; /usr/sbin/nft \'add rule inet "wg-easy-{{interface}}" forward oifname "{{interface}}" accept\'';

const defaultNftPostDown =
  '/usr/sbin/nft \'delete table ip "wg-easy-{{interface}}"\' 2>/dev/null || true' +
  '; /usr/sbin/nft \'delete table ip6 "wg-easy-{{interface}}"\' 2>/dev/null || true' +
  '; /usr/sbin/nft \'delete table inet "wg-easy-{{interface}}"\' 2>/dev/null || true';

function defaultIptablesPostUp(iface: string) {
  return `iptables -t nat -A POSTROUTING -s {{ipv4Cidr}} -o {{device}} -j MASQUERADE; iptables -A INPUT -p udp -m udp --dport {{port}} -j ACCEPT; iptables -A FORWARD -i ${iface} -j ACCEPT; iptables -A FORWARD -o ${iface} -j ACCEPT; ip6tables -t nat -A POSTROUTING -s {{ipv6Cidr}} -o {{device}} -j MASQUERADE; ip6tables -A INPUT -p udp -m udp --dport {{port}} -j ACCEPT; ip6tables -A FORWARD -i ${iface} -j ACCEPT; ip6tables -A FORWARD -o ${iface} -j ACCEPT;`;
}

function defaultIptablesPostDown(iface: string) {
  return `iptables -t nat -D POSTROUTING -s {{ipv4Cidr}} -o {{device}} -j MASQUERADE; iptables -D INPUT -p udp -m udp --dport {{port}} -j ACCEPT; iptables -D FORWARD -i ${iface} -j ACCEPT; iptables -D FORWARD -o ${iface} -j ACCEPT; ip6tables -t nat -D POSTROUTING -s {{ipv6Cidr}} -o {{device}} -j MASQUERADE; ip6tables -D INPUT -p udp -m udp --dport {{port}} -j ACCEPT; ip6tables -D FORWARD -i ${iface} -j ACCEPT; ip6tables -D FORWARD -o ${iface} -j ACCEPT;`;
}

/**
 * Replaces old default iptables hook commands with native nftables commands.
 * Custom hook text is preserved.
 */
async function normalizeInterfaceName(db: DBType) {
  const iface = WG_ENV.WG_INTERFACE;

  DB_DEBUG('Normalizing default hook commands...');

  await db.transaction(async (tx) => {
    const hooks = await tx.query.hooks.findFirst({
      where: eq(schema.hooks.id, 'wg0'),
    });

    if (!hooks) return;

    const defaultPostUps = [
      defaultIptablesPostUp('wg0'),
      defaultIptablesPostUp(iface),
    ];
    const defaultPostDowns = [
      defaultIptablesPostDown('wg0'),
      defaultIptablesPostDown(iface),
    ];

    const postUp = defaultPostUps.includes(hooks.postUp)
      ? defaultNftPostUp
      : hooks.postUp;
    const postDown = defaultPostDowns.includes(hooks.postDown)
      ? defaultNftPostDown
      : hooks.postDown;

    const needsUpdate = postUp !== hooks.postUp || postDown !== hooks.postDown;

    if (needsUpdate) {
      await tx
        .update(schema.hooks)
        .set({
          postUp,
          postDown,
        })
        .where(eq(schema.hooks.id, 'wg0'))
        .execute();
      DB_DEBUG('Default hook commands normalized.');
    }
  });
}

async function disableIpv6(db: DBType) {
  const ipv6PostUpMatch =
    '; /usr/sbin/nft \'delete table ip6 "wg-easy-{{interface}}"\' 2>/dev/null || true' +
    '; /usr/sbin/nft \'add table ip6 "wg-easy-{{interface}}"\' ' +
    '; /usr/sbin/nft \'add chain ip6 "wg-easy-{{interface}}" postrouting { type nat hook postrouting priority 100; policy accept; }\'' +
    '; /usr/sbin/nft \'add rule ip6 "wg-easy-{{interface}}" postrouting ip6 saddr {{ipv6Cidr}} oifname "{{device}}" masquerade\'';
  const ipv6PostDownMatch =
    '; /usr/sbin/nft \'delete table ip6 "wg-easy-{{interface}}"\' 2>/dev/null || true';

  await db.transaction(async (tx) => {
    const hooks = await tx.query.hooks.findFirst({
      where: eq(schema.hooks.id, 'wg0'),
    });

    if (!hooks) {
      throw new Error('Hooks not found');
    }

    const postUp = hooks.postUp.replace(ipv6PostUpMatch, '');
    const postDown = hooks.postDown.replace(ipv6PostDownMatch, '');

    if (postUp !== hooks.postUp || postDown !== hooks.postDown) {
      DB_DEBUG('Disabling IPv6 in hooks...');
      await tx
        .update(schema.hooks)
        .set({
          postUp,
          postDown,
        })
        .where(eq(schema.hooks.id, 'wg0'))
        .execute();
    } else {
      DB_DEBUG('IPv6 hooks already disabled, skipping...');
    }
  });
}
