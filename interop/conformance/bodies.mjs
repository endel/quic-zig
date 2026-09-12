// Scenario bodies, shared by every browser runner.
//
// Plain ES module with no Node imports so the hand-run page
// (interop/browser/wpt-tests.html) can import it directly in a browser, and the
// automated runner (interop/browser/run-wpt-tests.mjs) can import it in Node.
//
// A body is source text, not a function: the automated runner injects it into a
// page it generates. The preamble there defines wtUrl, createWT, readStream,
// readStreamText, datagramWriter, webTransportError and HANDLER.

export const BODIES = {
  'connect-echo': `
    const wt = createWT(HANDLER);
    await wt.ready;
    wt.close();
    await wt.closed;
    return 'ok';
  `,

  'client-close-code': `
    const wt = createWT(HANDLER);
    await wt.ready;
    wt.close({ closeCode: 7, reason: 'done' });
    const info = await wt.closed;
    if (info.closeCode !== 7) throw new Error('code=' + info.closeCode);
    if (info.reason !== 'done') throw new Error('reason=' + info.reason);
    return 'ok';
  `,

  'server-close-code0': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const info = await wt.closed;
    if (info.closeCode !== 0) throw new Error('code=' + info.closeCode);
    if (info.reason !== 'bye') throw new Error('reason=' + info.reason);
    return 'ok';
  `,

  'server-close-code42': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const info = await wt.closed;
    if (info.closeCode !== 42) throw new Error('code=' + info.closeCode);
    if (info.reason !== 'test') throw new Error('reason=' + info.reason);
    return 'ok';
  `,

  'server-close-code3999': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const info = await wt.closed;
    if (info.closeCode !== 3999) throw new Error('code=' + info.closeCode);
    return 'ok';
  `,

  'server-connection-close': `
    const wt = createWT(HANDLER);
    await wt.ready;
    // An abrupt QUIC close is an error, not a clean close: 'closed' must
    // reject. Resolving would mean we mistook a crash for a goodbye.
    try {
      await wt.closed;
    } catch (e) {
      return 'ok: ' + e.message;
    }
    throw new Error('closed resolved instead of rejecting');
  `,

  'bidi-echo-small': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const s = await wt.createBidirectionalStream();
    const w = s.writable.getWriter();
    await w.write(new TextEncoder().encode('hello'));
    await w.close();
    const text = await readStreamText(s.readable);
    wt.close();
    if (text !== 'hello') throw new Error('got "' + text + '"');
    return 'ok';
  `,

  'bidi-echo-3-streams': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const results = await Promise.all([0,1,2].map(async i => {
      const s = await wt.createBidirectionalStream();
      const w = s.writable.getWriter();
      const msg = 'msg' + i;
      await w.write(new TextEncoder().encode(msg));
      await w.close();
      const text = await readStreamText(s.readable);
      if (text !== msg) throw new Error('stream ' + i + ': "' + text + '"');
      return text;
    }));
    wt.close();
    return results.join(',');
  `,

  'bidi-echo-64kb': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const s = await wt.createBidirectionalStream();
    const w = s.writable.getWriter();
    const sent = new Uint8Array(65536);
    for (let i = 0; i < sent.length; i++) sent[i] = i & 0xff;
    const pump = w.write(sent).then(() => w.close());
    const recv = await readStream(s.readable);
    await pump;
    wt.close();
    if (recv.length !== 65536) throw new Error(recv.length + ' bytes');
    for (let i = 0; i < recv.length; i++) {
      if (recv[i] !== (i & 0xff)) throw new Error('corrupt at ' + i);
    }
    return 'ok (' + recv.length + 'B)';
  `,

  'uni-echo': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const sendStream = await wt.createUnidirectionalStream();
    const w = sendStream.getWriter();
    await w.write(new TextEncoder().encode('uni-test'));
    await w.close();
    const reader = wt.incomingUnidirectionalStreams.getReader();
    const { value: recvStream } = await reader.read();
    reader.releaseLock();
    const text = await readStreamText(recvStream);
    wt.close();
    if (text !== 'uni-test') throw new Error('got "' + text + '"');
    return 'ok';
  `,

  'uni-echo-64kb': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const sent = new Uint8Array(65536);
    for (let i = 0; i < sent.length; i++) sent[i] = i & 0xff;
    const sendStream = await wt.createUnidirectionalStream();
    const w = sendStream.getWriter();
    const pump = w.write(sent).then(() => w.close());
    const reader = wt.incomingUnidirectionalStreams.getReader();
    const { value: recvStream } = await reader.read();
    reader.releaseLock();
    const recv = await readStream(recvStream);
    await pump;
    wt.close();
    if (recv.length !== 65536) throw new Error(recv.length + ' bytes');
    return 'ok (' + recv.length + 'B)';
  `,

  'uni-multiple-streams': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const reader = wt.incomingUnidirectionalStreams.getReader();
    const seen = [];
    for (let i = 0; i < 5; i++) {
      const { value } = await Promise.race([
        reader.read(),
        new Promise((_, r) => setTimeout(() => r(new Error('got ' + seen.length + ' of 5')), 5000)),
      ]);
      seen.push(await readStreamText(value));
    }
    reader.releaseLock();
    wt.close();
    // WebTransport gives no ordering guarantee across streams, so check the
    // set, not the sequence — five distinct payloads, none lost or merged.
    const want = ['stream-0','stream-1','stream-2','stream-3','stream-4'];
    const sorted = [...seen].sort().join(',');
    if (sorted !== want.join(',')) throw new Error('got ' + seen.join(','));
    return 'ok';
  `,

  'datagram-echo': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const w = datagramWriter(wt);
    await w.write(new TextEncoder().encode('dg-test'));
    w.releaseLock();
    const r = wt.datagrams.readable.getReader();
    const { value } = await r.read();
    r.releaseLock();
    const text = new TextDecoder().decode(value);
    wt.close();
    if (text !== 'dg-test') throw new Error('got "' + text + '"');
    return 'ok';
  `,

  'datagram-maxsize': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const sz = wt.datagrams.maxDatagramSize;
    wt.close();
    if (sz <= 0) throw new Error('maxDatagramSize=' + sz);
    return 'ok (' + sz + ')';
  `,

  'datagram-length-echo': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const size = wt.datagrams.maxDatagramSize;
    const w = datagramWriter(wt);
    await w.write(new Uint8Array(size));
    w.releaseLock();
    const r = wt.datagrams.readable.getReader();
    const { value } = await r.read();
    r.releaseLock();
    const got = parseInt(new TextDecoder().decode(value), 10);
    wt.close();
    // A datagram at maxDatagramSize must arrive whole or not at all —
    // silent truncation is the failure this catches.
    if (got !== size) throw new Error('sent ' + size + ', server saw ' + got);
    return 'ok (' + size + 'B)';
  `,

  'server-abort-stream': `
    const wt = createWT(HANDLER);
    await wt.ready;
    // Write first: the handler resets whatever stream it hears from, so the
    // reset arrives on a stream we already hold and cannot be raced away.
    const stream = await wt.createBidirectionalStream();
    const w = stream.writable.getWriter();
    await w.write(new TextEncoder().encode('go'));
    try {
      await readStream(stream.readable);
    } catch (e) {
      wt.close();
      // The application code must survive the trip through the H3 error space
      // and back; a reset that arrives as 0 has lost it.
      if (e.streamErrorCode !== undefined && e.streamErrorCode !== 42) {
        throw new Error('streamErrorCode=' + e.streamErrorCode);
      }
      return 'ok: reset ' + e.streamErrorCode;
    }
    wt.close();
    throw new Error('stream completed instead of resetting');
  `,

  'client-abort-stream': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const s = await wt.createBidirectionalStream();
    const w = s.writable.getWriter();
    await w.write(new TextEncoder().encode('x'));
    w.releaseLock();
    // WritableStream.abort() takes a *reason*, not a code: pass a bare 42 and
    // the peer receives application code 0. The code rides in a
    // WebTransportError.
    await s.writable.abort(webTransportError(42));
    // The server reports back what code it saw, so this proves the reset
    // reached it rather than merely that abort() returned.
    const reader = wt.incomingUnidirectionalStreams.getReader();
    const { value: reply } = await reader.read();
    reader.releaseLock();
    const got = await readStreamText(reply);
    wt.close();
    if (got !== '42') throw new Error('server saw code ' + got);
    return 'ok';
  `,

  'server-stop-sending': `
    const wt = createWT(HANDLER);
    await wt.ready;
    const s = await wt.createBidirectionalStream();
    const w = s.writable.getWriter();
    await w.write(new TextEncoder().encode('start'));
    try {
      // Keep writing until the peer's STOP_SENDING lands on our side.
      for (let i = 0; i < 200; i++) {
        await w.write(new Uint8Array(4096));
      }
    } catch (e) {
      wt.close();
      if (e.streamErrorCode !== undefined && e.streamErrorCode !== 19) {
        throw new Error('streamErrorCode=' + e.streamErrorCode);
      }
      return 'ok: stopped ' + e.streamErrorCode;
    }
    wt.close();
    throw new Error('writes kept succeeding after STOP_SENDING');
  `,

  'server-drain': `
    const wt = createWT(HANDLER);
    await wt.ready;
    await wt.draining;
    // Draining is a warning, not a close: the session must still work.
    const s = await wt.createBidirectionalStream();
    const w = s.writable.getWriter();
    await w.write(new TextEncoder().encode('still here'));
    await w.close();
    wt.close();
    return 'ok';
  `,

  'wt-protocol-negotiation': `
    const wt = createWT(HANDLER, { protocols: ['nonesuch', 'echo'] });
    await wt.ready;
    const chosen = wt.protocol;
    wt.close();
    // The server prefers 'echo' and must say so; picking the unknown one, or
    // saying nothing, means the offer never round-tripped.
    if (chosen !== 'echo') throw new Error('protocol="' + chosen + '"');
    return 'ok (' + chosen + ')';
  `,
};

