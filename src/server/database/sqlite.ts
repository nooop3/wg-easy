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

const interfaceForwardRule =
  /(\bip6?tables\s+-(?:A|D)\s+FORWARD\s+-(?:i|o)\s+)\S+(\s+-j\s+ACCEPT;)/g;

const defaultNftIptablesPostUp =
  '/usr/sbin/iptables-nft -w -t nat -C POSTROUTING --source {{ipv4Cidr}} -j MASQUERADE 2>/dev/null || /usr/sbin/iptables-nft -w -t nat -A POSTROUTING --source {{ipv4Cidr}} -j MASQUERADE; ' +
  '/usr/sbin/iptables-nft -w -C INPUT --protocol udp --match udp --dport {{port}} -j ACCEPT 2>/dev/null || /usr/sbin/iptables-nft -w -A INPUT --protocol udp --match udp --dport {{port}} -j ACCEPT; ' +
  '/usr/sbin/iptables-nft -w -C FORWARD --in-interface {{interface}} -j ACCEPT 2>/dev/null || /usr/sbin/iptables-nft -w -A FORWARD --in-interface {{interface}} -j ACCEPT; ' +
  '/usr/sbin/iptables-nft -w -C FORWARD --out-interface {{interface}} -j ACCEPT 2>/dev/null || /usr/sbin/iptables-nft -w -A FORWARD --out-interface {{interface}} -j ACCEPT; ' +
  '/usr/sbin/ip6tables-nft -w -t nat -C POSTROUTING --source {{ipv6Cidr}} -j MASQUERADE 2>/dev/null || /usr/sbin/ip6tables-nft -w -t nat -A POSTROUTING --source {{ipv6Cidr}} -j MASQUERADE; ' +
  '/usr/sbin/ip6tables-nft -w -C INPUT --protocol udp --match udp --dport {{port}} -j ACCEPT 2>/dev/null || /usr/sbin/ip6tables-nft -w -A INPUT --protocol udp --match udp --dport {{port}} -j ACCEPT; ' +
  '/usr/sbin/ip6tables-nft -w -C FORWARD --in-interface {{interface}} -j ACCEPT 2>/dev/null || /usr/sbin/ip6tables-nft -w -A FORWARD --in-interface {{interface}} -j ACCEPT; ' +
  '/usr/sbin/ip6tables-nft -w -C FORWARD --out-interface {{interface}} -j ACCEPT 2>/dev/null || /usr/sbin/ip6tables-nft -w -A FORWARD --out-interface {{interface}} -j ACCEPT;';

const defaultNftIptablesPostDown =
  'while /usr/sbin/iptables-nft -w -t nat -D POSTROUTING --source {{ipv4Cidr}} -j MASQUERADE 2>/dev/null; do :; done; ' +
  'while /usr/sbin/iptables-nft -w -D INPUT --protocol udp --match udp --dport {{port}} -j ACCEPT 2>/dev/null; do :; done; ' +
  'while /usr/sbin/iptables-nft -w -D FORWARD --in-interface {{interface}} -j ACCEPT 2>/dev/null; do :; done; ' +
  'while /usr/sbin/iptables-nft -w -D FORWARD --out-interface {{interface}} -j ACCEPT 2>/dev/null; do :; done; ' +
  'while /usr/sbin/ip6tables-nft -w -t nat -D POSTROUTING --source {{ipv6Cidr}} -j MASQUERADE 2>/dev/null; do :; done; ' +
  'while /usr/sbin/ip6tables-nft -w -D INPUT --protocol udp --match udp --dport {{port}} -j ACCEPT 2>/dev/null; do :; done; ' +
  'while /usr/sbin/ip6tables-nft -w -D FORWARD --in-interface {{interface}} -j ACCEPT 2>/dev/null; do :; done; ' +
  'while /usr/sbin/ip6tables-nft -w -D FORWARD --out-interface {{interface}} -j ACCEPT 2>/dev/null; do :; done;';

function defaultIptablesPostUp(iface: string) {
  return `iptables -t nat -A POSTROUTING -s {{ipv4Cidr}} -o {{device}} -j MASQUERADE; iptables -A INPUT -p udp -m udp --dport {{port}} -j ACCEPT; iptables -A FORWARD -i ${iface} -j ACCEPT; iptables -A FORWARD -o ${iface} -j ACCEPT; ip6tables -t nat -A POSTROUTING -s {{ipv6Cidr}} -o {{device}} -j MASQUERADE; ip6tables -A INPUT -p udp -m udp --dport {{port}} -j ACCEPT; ip6tables -A FORWARD -i ${iface} -j ACCEPT; ip6tables -A FORWARD -o ${iface} -j ACCEPT;`;
}

function defaultIptablesPostDown(iface: string) {
  return `iptables -t nat -D POSTROUTING -s {{ipv4Cidr}} -o {{device}} -j MASQUERADE; iptables -D INPUT -p udp -m udp --dport {{port}} -j ACCEPT; iptables -D FORWARD -i ${iface} -j ACCEPT; iptables -D FORWARD -o ${iface} -j ACCEPT; ip6tables -t nat -D POSTROUTING -s {{ipv6Cidr}} -o {{device}} -j MASQUERADE; ip6tables -D INPUT -p udp -m udp --dport {{port}} -j ACCEPT; ip6tables -D FORWARD -i ${iface} -j ACCEPT; ip6tables -D FORWARD -o ${iface} -j ACCEPT;`;
}

/**
 * Replaces default hook commands with explicit iptables-nft commands. Custom
 * hook text is preserved.
 */
async function normalizeInterfaceName(db: DBType) {
  const iface = WG_ENV.WG_INTERFACE;

  DB_DEBUG(`Normalizing hook interface names to '${iface}'...`);

  await db.transaction(async (tx) => {
    const hooks = await tx.query.hooks.findFirst({
      where: eq(schema.hooks.id, 'wg0'),
    });

    if (!hooks) return;

    const defaultPostUps = [
      defaultIptablesPostUp('wg0'),
      defaultIptablesPostUp(iface),
      defaultNftIptablesPostUp,
    ];
    const defaultPostDowns = [
      defaultIptablesPostDown('wg0'),
      defaultIptablesPostDown(iface),
      defaultNftIptablesPostDown,
    ];

    const hasNativeNftHooks = hooks.postUp.includes('/usr/sbin/nft ');
    const postUp =
      defaultPostUps.includes(hooks.postUp) || hasNativeNftHooks
        ? defaultNftIptablesPostUp
        : hooks.postUp.replaceAll(interfaceForwardRule, `$1${iface}$2`);
    const postDown =
      defaultPostDowns.includes(hooks.postDown) || hasNativeNftHooks
        ? defaultNftIptablesPostDown
        : hooks.postDown.replaceAll(interfaceForwardRule, `$1${iface}$2`);

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
      DB_DEBUG(`Hook interface names normalized to '${iface}'.`);
    }
  });
}

async function disableIpv6(db: DBType) {
  const iface = WG_ENV.WG_INTERFACE;
  // This should match the initial value migration after normalizeInterfaceName runs.
  const postUpMatches = [
    ` ip6tables -t nat -A POSTROUTING -s {{ipv6Cidr}} -o {{device}} -j MASQUERADE; ip6tables -A INPUT -p udp -m udp --dport {{port}} -j ACCEPT; ip6tables -A FORWARD -i ${iface} -j ACCEPT; ip6tables -A FORWARD -o ${iface} -j ACCEPT;`,
    ` /usr/sbin/ip6tables-nft -w -t nat -C POSTROUTING --source {{ipv6Cidr}} -j MASQUERADE 2>/dev/null || /usr/sbin/ip6tables-nft -w -t nat -A POSTROUTING --source {{ipv6Cidr}} -j MASQUERADE; /usr/sbin/ip6tables-nft -w -C INPUT --protocol udp --match udp --dport {{port}} -j ACCEPT 2>/dev/null || /usr/sbin/ip6tables-nft -w -A INPUT --protocol udp --match udp --dport {{port}} -j ACCEPT; /usr/sbin/ip6tables-nft -w -C FORWARD --in-interface {{interface}} -j ACCEPT 2>/dev/null || /usr/sbin/ip6tables-nft -w -A FORWARD --in-interface {{interface}} -j ACCEPT; /usr/sbin/ip6tables-nft -w -C FORWARD --out-interface {{interface}} -j ACCEPT 2>/dev/null || /usr/sbin/ip6tables-nft -w -A FORWARD --out-interface {{interface}} -j ACCEPT;`,
  ];
  const postDownMatches = [
    ` ip6tables -t nat -D POSTROUTING -s {{ipv6Cidr}} -o {{device}} -j MASQUERADE; ip6tables -D INPUT -p udp -m udp --dport {{port}} -j ACCEPT; ip6tables -D FORWARD -i ${iface} -j ACCEPT; ip6tables -D FORWARD -o ${iface} -j ACCEPT;`,
    ` while /usr/sbin/ip6tables-nft -w -t nat -D POSTROUTING --source {{ipv6Cidr}} -j MASQUERADE 2>/dev/null; do :; done; while /usr/sbin/ip6tables-nft -w -D INPUT --protocol udp --match udp --dport {{port}} -j ACCEPT 2>/dev/null; do :; done; while /usr/sbin/ip6tables-nft -w -D FORWARD --in-interface {{interface}} -j ACCEPT 2>/dev/null; do :; done; while /usr/sbin/ip6tables-nft -w -D FORWARD --out-interface {{interface}} -j ACCEPT 2>/dev/null; do :; done;`,
  ];

  await db.transaction(async (tx) => {
    const hooks = await tx.query.hooks.findFirst({
      where: eq(schema.hooks.id, 'wg0'),
    });

    if (!hooks) {
      throw new Error('Hooks not found');
    }

    const postUp = postUpMatches.reduce(
      (value, match) => value.replace(match, ''),
      hooks.postUp
    );
    const postDown = postDownMatches.reduce(
      (value, match) => value.replace(match, ''),
      hooks.postDown
    );

    if (postUp !== hooks.postUp || postDown !== hooks.postDown) {
      DB_DEBUG('Disabling IPv6 in Post Up hooks...');
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
