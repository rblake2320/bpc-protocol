import { describe, expect, it, vi } from 'vitest';
import { getEventListeners } from 'node:events';
import {
  AmbiguousCommitError,
  ConnectionDisposalError,
  NodePostgresTransactor,
  PostCommitReleaseError,
  type NodePostgresClient,
} from '../src/index.js';

const result = (command = 'SELECT') => ({ rows: [], rowCount: 0, command });

function defaultQuery(sql: string, params?: unknown[]) {
  if (sql.startsWith('BEGIN')) return Promise.resolve(result('BEGIN'));
  if (sql.startsWith('SET LOCAL statement_timeout')) return Promise.resolve(result('SET'));
  if (sql.startsWith('LOCK TABLE')) return Promise.resolve(result('LOCK'));
  if (sql.includes("set_config('statement_timeout'")) {
    return Promise.resolve({ rows: [{ statement_timeout: `${params?.[0]}ms` }], rowCount: 1, command: 'SELECT' });
  }
  if (sql.includes("current_setting('statement_timeout')")) {
    return Promise.resolve({ rows: [{ statement_timeout_ms: '30000' }], rowCount: 1, command: 'SELECT' });
  }
  if (sql.includes('txid_current()')) return Promise.resolve({rows:[{txid:'tx-1'}],rowCount:1,command:'SELECT'});
  if (sql==='DISCARD ALL') return Promise.resolve(result('DISCARD'));
  return Promise.resolve(result(sql === 'COMMIT' ? 'COMMIT' : 'SELECT'));
}

function clientWith(query = vi.fn(defaultQuery)) {
  return { query, release: vi.fn() } satisfies NodePostgresClient;
}

describe('NodePostgresTransactor', () => {
  it('commits a serializable, statement-timeout-bounded transaction', async () => {
    const client = clientWith();
    const db = new NodePostgresTransactor({ connect: async () => client });
    await expect(db.transaction(async (exec) => {
      await exec.query('SELECT 1');
      return 7;
    })).resolves.toBe(7);
    expect(client.query.mock.calls.map((c) => c[0])).toEqual([
      'BEGIN ISOLATION LEVEL SERIALIZABLE',
      "SELECT set_config('statement_timeout', $1, true) AS statement_timeout",
      "SELECT (EXTRACT(EPOCH FROM current_setting('statement_timeout')::interval) * 1000)::bigint::text AS statement_timeout_ms",
      'SELECT txid_current()::text AS txid',
      'SELECT 1',
      'SELECT txid_current()::text AS txid',
      'COMMIT',
      'DISCARD ALL',
    ]);
    expect(client.release).toHaveBeenCalledWith(false);
  });

  it('acquires migration authority locks before the first SELECT/readback', async () => {
    const client=clientWith();
    const db=new NodePostgresTransactor({connect:async()=>client});
    await db.transactionWithInitialExclusiveLocks([
      {schema:'tenant_a',table:'bpc_pairs'}, {schema:'tenant_a',table:'bpc_pending'},
    ], async(exec)=>{await exec.query('SELECT authority');});
    expect(client.query.mock.calls.map((c)=>c[0])).toEqual([
      'BEGIN ISOLATION LEVEL SERIALIZABLE',
      "SET LOCAL statement_timeout = '30000ms'",
      'LOCK TABLE "tenant_a"."bpc_pairs", "tenant_a"."bpc_pending" IN ACCESS EXCLUSIVE MODE',
      "SELECT (EXTRACT(EPOCH FROM current_setting('statement_timeout')::interval) * 1000)::bigint::text AS statement_timeout_ms",
      'SELECT txid_current()::text AS txid',
      'SELECT authority',
      'SELECT txid_current()::text AS txid',
      'COMMIT',
      'DISCARD ALL',
    ]);
  });

  it('rejects empty, duplicate, or unsafe initial authority lock identifiers', async () => {
    const db=new NodePostgresTransactor({connect:async()=>clientWith()});
    await expect(db.transactionWithInitialExclusiveLocks([],async()=>1)).rejects.toThrow(/1\.\.16/);
    await expect(db.transactionWithInitialExclusiveLocks([{schema:'public;drop',table:'x'}],async()=>1)).rejects.toThrow(/identifiers/);
    await expect(db.transactionWithInitialExclusiveLocks([{schema:'Upper',table:'x'}],async()=>1)).rejects.toThrow(/identifiers/);
    await expect(db.transactionWithInitialExclusiveLocks([{schema:'has$dollar',table:'x'}],async()=>1)).rejects.toThrow(/identifiers/);
    await expect(db.transactionWithInitialExclusiveLocks([{schema:'public',table:'x'},{schema:'public',table:'x'}],async()=>1)).rejects.toThrow(/unique/);
  });

  it('rejects transaction/session control and multi-statements before dispatch', async () => {
    for(const sql of [
      'COMMIT','/* sneaky */ COMMIT','BEGIN','START TRANSACTION','ROLLBACK','ABORT',
      'SAVEPOINT x','RELEASE SAVEPOINT x','PREPARE TRANSACTION \'x\'','SET TRANSACTION READ ONLY',
      'RESET ALL','DISCARD ALL','CALL dangerous()','DO $$ BEGIN END $$',
      'SELECT 1; COMMIT','COMMIT; SELECT 1',
    ]){
      const client=clientWith();const db=new NodePostgresTransactor({connect:async()=>client});
      await expect(db.transaction(exec=>exec.query(sql))).rejects.toThrow(/forbids|exactly one statement/);
      const matching=client.query.mock.calls.filter(call=>call[0]===sql).length;
      expect(matching).toBe(sql==='ROLLBACK'?1:0); // the one ROLLBACK is adapter cleanup, not callback dispatch
      expect(client.query).toHaveBeenCalledWith('ROLLBACK');
    }
    const client=clientWith();const db=new NodePostgresTransactor({connect:async()=>client});
    await expect(db.transaction(exec=>exec.query("SELECT 'COMMIT; ROLLBACK', $$BEGIN; END$$ /* ; */"))).resolves.toBeDefined();
  });

  it('rolls back and destroys the connection on callback failure', async () => {
    const client = clientWith();
    const db = new NodePostgresTransactor({ connect: async () => client });
    await expect(db.transaction(async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
    expect(client.release).toHaveBeenCalledWith(true);
  });

  it('fails closed when COMMIT is not confirmed', async () => {
    const client = clientWith(vi.fn(async (sql: string, params?: unknown[]) => {
      if (sql === 'COMMIT') return result('ROLLBACK');
      return defaultQuery(sql, params);
    }));
    const db = new NodePostgresTransactor({ connect: async () => client });
    await expect(db.transaction(async () => 1)).rejects.toThrow('COMMIT was not confirmed');
    expect(client.release).toHaveBeenCalledWith(true);
  });

  it('classifies a changed transaction-continuity sentinel as ambiguous', async () => {
    let sentinels=0;
    const client=clientWith(vi.fn(async(sql:string,params?:unknown[])=>{
      if(sql.includes('txid_current()'))return{rows:[{txid:`tx-${++sentinels}`}],rowCount:1,command:'SELECT'};
      return defaultQuery(sql,params);
    }));
    const db=new NodePostgresTransactor({connect:async()=>client});
    await expect(db.transaction(async()=>1)).rejects.toBeInstanceOf(AmbiguousCommitError);
    expect(client.query.mock.calls.some(call=>call[0]==='COMMIT')).toBe(false);
    expect(client.release).toHaveBeenCalledWith(true);
  });

  it('destroys a committed connection when DISCARD ALL is not confirmed', async () => {
    const client=clientWith(vi.fn(async(sql:string,params?:unknown[])=>sql==='DISCARD ALL'?result('SELECT'):defaultQuery(sql,params)));
    const db=new NodePostgresTransactor({connect:async()=>client});
    await expect(db.transaction(async()=>1)).rejects.toMatchObject({name:'PostCommitReleaseError',committed:true});
    expect(client.release).toHaveBeenCalledWith(true);
  });

  it('retries only bounded serialization failures when explicitly enabled', async () => {
    let attempt = 0;
    const clients: NodePostgresClient[] = [];
    const db = new NodePostgresTransactor({
      connect: async () => {
        attempt++;
        const client = clientWith();
        clients.push(client);
        return client;
      },
    }, { maxSerializationRetries: 1, retryBaseDelayMs: 1 });
    await expect(db.transaction(async () => {
      if (attempt === 1) throw Object.assign(new Error('serialization'), { code: '40001' });
      return 'ok';
    })).resolves.toBe('ok');
    expect(clients).toHaveLength(2);
    expect(clients[0].release).toHaveBeenCalledWith(true);
  });

  it('bounds acquisition and destroys a late connection', async () => {
    const client = clientWith();
    let resolve!: (value: NodePostgresClient) => void;
    const pending = new Promise<NodePostgresClient>((r) => { resolve = r; });
    const db = new NodePostgresTransactor({ connect: () => pending }, { acquireTimeoutMs: 5 });
    await expect(db.transaction(async () => 1)).rejects.toThrow('acquisition timed out');
    resolve(client);
    await new Promise((r) => setTimeout(r, 0));
    expect(client.release).toHaveBeenCalledWith(true);
  });

  it('aborts and destroys an active connection', async () => {
    const client = clientWith();
    const db = new NodePostgresTransactor({ connect: async () => client });
    const controller = new AbortController();
    const tx = db.transaction(async () => new Promise<number>(() => {}), { signal: controller.signal });
    controller.abort(new Error('stop'));
    await expect(tx).rejects.toThrow('stop');
    expect(client.release).toHaveBeenCalledWith(true);
  });

  it.each(['BEGIN', 'SET', 'WORK', 'COMMIT'])('bounds a hung %s without a caller signal', async (stage) => {
    const query = vi.fn(async (sql: string, params?: unknown[]) => {
      const isStage =
        (stage === 'BEGIN' && sql.startsWith('BEGIN'))
        || (stage === 'SET' && sql.includes("set_config('statement_timeout'"))
        || (stage === 'WORK' && sql === 'SELECT work')
        || (stage === 'COMMIT' && sql === 'COMMIT');
      if (isStage) return new Promise<never>(() => {});
      return defaultQuery(sql, params);
    });
    const client = clientWith(query);
    const db = new NodePostgresTransactor(
      { connect: async () => client },
      { transactionTimeoutMs: 10, rollbackTimeoutMs: 5 },
    );
    const expectation = expect(db.transaction(async (exec) => {
      if (stage === 'WORK') await exec.query('SELECT work');
      return 1;
    })).rejects;
    if (stage === 'COMMIT') await expectation.toBeInstanceOf(AmbiguousCommitError);
    else await expectation.toThrow('deadline exceeded');
    expect(client.release).toHaveBeenCalledWith(true);
  });

  it('requires confirmed BEGIN and timeout setup before exposing the executor', async () => {
    const badBegin = clientWith(vi.fn(async () => result('SELECT')));
    await expect(new NodePostgresTransactor({ connect: async () => badBegin }).transaction(async () => 1))
      .rejects.toThrow('BEGIN was not confirmed');

    const badTimeout = clientWith(vi.fn(async (sql: string, params?: unknown[]) => {
      if (sql.includes('set_config')) return { rows: [], rowCount: 0, command: 'SELECT' };
      return defaultQuery(sql, params);
    }));
    await expect(new NodePostgresTransactor({ connect: async () => badTimeout }).transaction(async () => 1))
      .rejects.toThrow('statement_timeout setup was not confirmed');
  });

  it('removes caller abort listeners after success and retry', async () => {
    const controller = new AbortController();
    let attempt = 0;
    const db = new NodePostgresTransactor({ connect: async () => clientWith() }, {
      maxSerializationRetries: 1,
      retryBaseDelayMs: 1,
    });
    await db.transaction(async () => {
      attempt++;
      if (attempt === 1) throw Object.assign(new Error('retry'), { code: '40001' });
      return 1;
    }, { signal: controller.signal });
    expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
  });

  it('surfaces normal release failure without a second release attempt', async () => {
    const release = vi.fn((destroy?: boolean | Error) => {
      if (destroy !== true) throw new Error('pool release failed');
    });
    const client = { query: vi.fn(defaultQuery), release } satisfies NodePostgresClient;
    const db = new NodePostgresTransactor({ connect: async () => client });
    await expect(db.transaction(async () => 42)).rejects.toMatchObject({
      name: 'PostCommitReleaseError',
      committed: true,
    });
    expect(release.mock.calls).toEqual([[false]]);
  });

  it('reports a lost COMMIT response as non-retryable outcome ambiguity', async () => {
    let serverCommitted = false;
    const client = clientWith(vi.fn(async (sql: string, params?: unknown[]) => {
      if (sql === 'COMMIT') {
        serverCommitted = true;
        return new Promise<never>(() => {});
      }
      return defaultQuery(sql, params);
    }));
    const db = new NodePostgresTransactor(
      { connect: async () => client },
      { transactionTimeoutMs: 10 },
    );
    const error = await db.transaction(async () => 1).catch((caught) => caught);
    expect(serverCommitted).toBe(true);
    expect(error).toBeInstanceOf(AmbiguousCommitError);
    expect(error).toMatchObject({ committed: 'unknown' });
    expect((error as { code?: string }).code).toBeUndefined();
  });

  it.each([
    ['ROLLBACK', false],
    ['SELECT', true],
    ['UNKNOWN', true],
    [undefined, true],
  ] as const)('classifies COMMIT response tag %s conservatively', async (command, ambiguous) => {
    const client = clientWith(vi.fn(async (sql: string, params?: unknown[]) => {
      if (sql === 'COMMIT') return { rows: [], rowCount: 0, command };
      return defaultQuery(sql, params);
    }));
    const db = new NodePostgresTransactor({ connect: async () => client });
    const error = await db.transaction(async () => 1).catch((caught) => caught);
    if (ambiguous) expect(error).toBeInstanceOf(AmbiguousCommitError);
    else expect(error).not.toBeInstanceOf(AmbiguousCommitError);
  });

  it('does not start a query retained by a callback after abort', async () => {
    const controller = new AbortController();
    let wake!: () => void;
    const gate = new Promise<void>((resolve) => { wake = resolve; });
    const client = clientWith();
    const db = new NodePostgresTransactor({ connect: async () => client });
    const tx = db.transaction(async (exec) => {
      await gate;
      await exec.query('SELECT AFTER_ABORT');
    }, { signal: controller.signal });
    await new Promise((resolve) => setTimeout(resolve, 0));
    controller.abort(new Error('stop'));
    await expect(tx).rejects.toThrow('stop');
    const countAtAbort = client.query.mock.calls.length;
    wake();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(client.query.mock.calls).toHaveLength(countAtAbort);
  });

  it('attempts destroy exactly once and surfaces disposal failure', async () => {
    const observed: unknown[] = [];
    const client = clientWith();
    client.release = vi.fn(() => { throw new Error('destroy failed'); });
    const db = new NodePostgresTransactor({ connect: async () => client }, {
      transactionTimeoutMs: 10,
      onDisposalError: (error) => observed.push(error),
    });
    const error = await db.transaction(async () => new Promise<never>(() => {})).catch((caught) => caught);
    expect(error).toBeInstanceOf(ConnectionDisposalError);
    expect(client.release).toHaveBeenCalledTimes(1);
    expect(observed).toHaveLength(1);
  });

  it('consumes an asynchronously rejecting disposal observer', async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (error: unknown) => unhandled.push(error);
    process.on('unhandledRejection', onUnhandled);
    try {
      const client = clientWith();
      client.release = vi.fn(() => { throw new Error('destroy failed'); });
      const db = new NodePostgresTransactor({ connect: async () => client }, {
        transactionTimeoutMs: 10,
        onDisposalError: async () => { throw new Error('telemetry failed'); },
      });
      await db.transaction(async () => new Promise<never>(() => {})).catch(() => {});
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(unhandled).toEqual([]);
    } finally {
      process.removeListener('unhandledRejection', onUnhandled);
    }
  });

  it('exports public outcome errors from the package root', () => {
    expect(AmbiguousCommitError).toBeTypeOf('function');
    expect(PostCommitReleaseError).toBeTypeOf('function');
    expect(ConnectionDisposalError).toBeTypeOf('function');
  });

  it('rejects unsafe timeout and retry configuration', () => {
    const pool = { connect: async () => clientWith() };
    expect(() => new NodePostgresTransactor(pool, { statementTimeoutMs: 0 })).toThrow();
    expect(() => new NodePostgresTransactor(pool, { maxSerializationRetries: -1 })).toThrow();
    expect(() => new NodePostgresTransactor(pool, { maxSerializationRetries: 101 })).toThrow();
    expect(() => new NodePostgresTransactor(pool, { acquireTimeoutMs: 2 ** 31 })).toThrow();
  });
});
