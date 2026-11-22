"""Retryable ownership of disposable test forwarders, independent of generators.

Only this owner starts its threads. No makefile/dup/detach references are allowed.
The registry contains live handles and must never be serialized. Failure codes
are fixed; successful resource recovery never erases failed evidence.

The socket and thread bounds limit handles in use at the same time. A stream
leaves the registry only once it is closed, and a thread only once its own
target wrapper finished and it is no longer alive; both happen at the next
allocation, so the last connection's handles stay owned for cleanup and checks.
A thread whose start was never proven stays owned forever. When a bound trips,
the first trip is kept with its time and the listener is closed at once, so a
new dial is refused instead of waiting unanswered in the listen backlog.
"""

import socket
import errno
import threading
import time


class Forwarder:
    maximum_streams = 128  # Concurrent sockets: 64 relayed connections.
    maximum_threads = 129  # One producer and two relays per connection.

    def __init__(self, *, socket_factory=socket.socket, thread_factory=threading.Thread):
        self.lock = threading.RLock()
        self.stopping = threading.Event()
        self.socket_factory, self.thread_factory = socket_factory, thread_factory
        self.listeners, self.streams, self.workers, self.threads = [], [], [], []
        self.failures = set()
        self.tripped = None

    def _close(self, stream, *, listener=False, shutdown=True):
        if stream.fileno() == -1:
            return
        if not listener and shutdown:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError as error:
                if error.errno not in (errno.ENOTCONN, errno.EINVAL):
                    self.failures.add('SHUTDOWN_FAILED')
            except BaseException:
                self.failures.add('SHUTDOWN_FAILED')
        try:
            stream.close()
        except BaseException:
            self.failures.add('CLOSE_FAILED')

    def _trip(self, code):
        # Caller holds self.lock. Keep plain data only: the trip is reported, not the registry.
        self.failures.add(code)
        if self.tripped is None:
            self.tripped = dict(
                code=code, monotonicNS=time.monotonic_ns(),
                wallTime=time.strftime('%Y-%m-%dT%H:%M:%S%z'),
                streams=len(self.streams), threads=len(self.threads),
                maximumStreams=self.maximum_streams, maximumThreads=self.maximum_threads)
        self.stopping.set()
        for stream in self.listeners:
            self._close(stream, listener=True)

    def _prune_streams(self):
        # Caller holds self.lock. In place: callers may hold aliases of the list.
        self.streams[:] = [stream for stream in self.streams if stream.fileno() != -1]

    def _prune_threads(self):
        # Caller holds self.lock. Only a started thread whose wrapper finished and which is
        # no longer alive is forgotten; 'starting' and 'uncertain' rows are never dropped.
        done = [row for row in self.threads
                if row['state'] == 'started' and row['finished'].is_set()
                and not row['thread'].is_alive()]
        if done:
            rows, ended = {id(row) for row in done}, {id(row['thread']) for row in done}
            self.threads[:] = [row for row in self.threads if id(row) not in rows]
            self.workers[:] = [thread for thread in self.workers if id(thread) not in ended]

    def new_socket(self, *, listener=False):
        # Allocation and registration are one lifecycle operation; no connect here.
        with self.lock:
            if self.stopping.is_set():
                self.failures.add('ACQUISITION_AFTER_STOP')
                raise RuntimeError('Forwarder is stopping')
            if not listener:
                self._prune_streams()
            if (listener and self.listeners) or (
                    not listener and len(self.streams) >= self.maximum_streams):
                self._trip('SOCKET_LIMIT')
                raise RuntimeError('Forwarder socket bound')
            try:
                stream = self.socket_factory()
            except BaseException:
                self.failures.add('SOCKET_CONSTRUCTION')
                self.stopping.set()
                raise
            (self.listeners if listener else self.streams).append(stream)
            if self.stopping.is_set():
                self._close(stream, listener=listener)
            return stream

    def adopt(self, stream):
        with self.lock:
            self._prune_streams()
            self.streams.append(stream)
            if len(self.streams) > self.maximum_streams:
                self._trip('STREAM_LIMIT')
            if self.stopping.is_set():
                self._close(stream)
                return False
            return True

    def release(self, *streams):
        """Close owned streams whose relays have all returned; nothing waits on them."""
        with self.lock:
            for stream in streams:
                if stream is not None and any(stream is owned for owned in self.streams):
                    self._close(stream, shutdown=False)  # No reader is left to wake.

    def start(self, target, args=(), *, producer=False):
        # Stop cannot interleave between the decision, registration and launch.
        with self.lock:
            if self.stopping.is_set():
                return None
            self._prune_threads()
            if len(self.threads) >= self.maximum_threads:
                self._trip('THREAD_LIMIT')
                raise RuntimeError('Forwarder thread bound')
            entered, finished = threading.Event(), threading.Event()
            def run():
                entered.set()
                try:
                    target(*args)
                except BaseException:
                    with self.lock:
                        self.failures.add('THREAD_RUN')
                    try:
                        self.interrupt()
                    except BaseException:
                        with self.lock:
                            self.failures.add('THREAD_RUN_CLEANUP')
                finally:
                    finished.set()
            try:
                thread = self.thread_factory(target=run, args=(), daemon=True)
            except BaseException:
                self.failures.add('THREAD_CONSTRUCTION')
                self.stopping.set()
                raise
            row = dict(thread=thread, state='starting', entered=entered, finished=finished)
            self.threads.append(row)
            if not producer:
                self.workers.append(thread)
            try:
                thread.start()
            except BaseException:
                # ident/is_alive cannot distinguish an unfinished bootstrap from
                # refusal. Only our target entry or a successful start return can.
                row['state'] = 'started' if entered.is_set() else 'uncertain'
                self.failures.add('THREAD_START')
                self.stopping.set()
                raise
            row['state'] = 'started'
            return thread

    def _snapshot(self):
        with self.lock:
            return list(self.listeners), list(self.streams), list(self.threads)

    def _join(self, rows, deadline):
        for row in rows:
            thread = row['thread']
            if thread is threading.current_thread():
                continue
            if row['state'] != 'started' and not row['entered'].is_set():
                continue  # Never join an unstarted or uncertain thread.
            try:
                thread.join(timeout=max(0, deadline - time.monotonic()))
            except BaseException:
                with self.lock:
                    self.failures.add('JOIN_FAILED')

    def interrupt(self):
        """Transport/startup failure: close handles without joining the caller."""
        with self.lock:
            self.failures.add('TRANSPORT_INTERRUPTED')
            self.stopping.set()
            for stream in self.listeners:
                self._close(stream, listener=True)
            for stream in self.streams:
                self._close(stream)

    def cleanup(self, *, grace=6, timeout=8):
        assert 0 <= grace <= timeout <= 30
        started = time.monotonic()
        with self.lock:
            self.stopping.set()
            for stream in self.listeners:
                self._close(stream, listener=True)
        # Preserve queued final/logout bytes while already admitted workers drain.
        self._join(self._snapshot()[2], started + grace)
        with self.lock:
            if any(row['thread'].is_alive() for row in self.threads):
                self.failures.add('FORCED_TRANSPORT_CLOSE')
            for stream in self.streams:
                self._close(stream)
        self._join(self._snapshot()[2], started + timeout)
        # Late handles are retained and closed even after a consumed generator.
        with self.lock:
            for stream in self.streams:
                self._close(stream)
        return self.closed()

    def closed(self):
        with self.lock:
            for row in self.threads:
                if row['state'] == 'uncertain' and row['entered'].is_set():
                    row['state'] = 'started'
            return (self.stopping.is_set()
                    and all(row['state'] not in ('starting', 'uncertain')
                            and not row['thread'].is_alive() for row in self.threads)
                    and all(stream.fileno() == -1 for stream in self.listeners + self.streams))
