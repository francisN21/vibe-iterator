/**
 * WebSocket client — connects to /ws and dispatches events to registered handlers.
 */
class ScanWebSocket {
  constructor() {
    this._handlers = {};
    this._ws = null;
    this._reconnectAttempts = 0;
    this._maxReconnects = 15;
    this._closed = false;
  }

  /** Register a handler for a specific event type. Use '*' for all events. */
  on(type, handler) {
    this._handlers[type] = handler;
    return this;
  }

  connect() {
    if (this._closed) return;
    const wsUrl = `ws://${window.location.host}/ws`;
    this._ws = new WebSocket(wsUrl);

    this._ws.onopen = () => {
      this._reconnectAttempts = 0;
      this._dispatch({ type: '_connected', timestamp: new Date().toISOString(), data: {} });
    };

    this._ws.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data);
        this._dispatch(event);
      } catch (err) {
        console.error('[WS] parse error:', err);
      }
    };

    this._ws.onclose = () => {
      this._dispatch({ type: '_disconnected', timestamp: new Date().toISOString(), data: {} });
      if (!this._closed && this._reconnectAttempts < this._maxReconnects) {
        this._reconnectAttempts++;
        const delay = Math.min(1000 * this._reconnectAttempts, 8000);
        setTimeout(() => this.connect(), delay);
      }
    };

    this._ws.onerror = () => {
      // onclose fires after onerror, reconnect happens there
    };
  }

  close() {
    this._closed = true;
    if (this._ws) this._ws.close();
  }

  _dispatch(event) {
    const handler = this._handlers[event.type] || this._handlers['*'];
    if (handler) {
      try { handler(event); } catch (err) { console.error('[WS] handler error:', err); }
    }
  }
}
